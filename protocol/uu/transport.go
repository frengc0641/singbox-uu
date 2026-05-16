package uu

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ─── Message Types (matching uuclient.py / uuserver.py) ───

const (
	MsgStart   byte = 0x00 // Start VPN link
	MsgNew     byte = 0x01 // New session
	MsgData    byte = 0x02 // Data transfer
	MsgClose   byte = 0x03 // Close session
	MsgAck     byte = 0x04 // Speed ack
	MsgResend  byte = 0x05 // Request resend (list of lost seq)
	MsgResendR byte = 0x06 // Resend response
)

// ─── Packet Wire Format ───
// [nonce:8][encrypted_header:8][encrypted_payload:...]
// header (plaintext): [seq:4][session_id:2][msg_type:1][checksum:1] = 8 bytes
// checksum = blake2b(header[0:7], digest_size=1)

const (
	NonceSize       = 8
	HeaderSize      = 8 // 4(seq) + 2(session) + 1(type) + 1(checksum)
	HeaderPlainSize = 7 // without checksum
	DefaultMTU      = 1380
	MaxTXBuffer     = 20000
	DefaultPassword = "ch0641ng"
	ConnectPassword = "040588"
)

// ─── Loss Recovery Config ───

type LossConfig struct {
	RequestGrace float64
	RetryBase    float64
	RetryMax     float64
	MaxRetry     int
	SkipAfter    float64
	BatchSize    int
}

func DefaultLossConfig() LossConfig {
	return LossConfig{
		RequestGrace: 0.18,
		RetryBase:    0.45,
		RetryMax:     3.0,
		MaxRetry:     6,
		SkipAfter:    8.0,
		BatchSize:    160,
	}
}

// ─── Speed Config ───

type SpeedConfig struct {
	InitSpeed float64 // bytes/sec, e.g. 4.5e6
	MinSpeed  float64 // bytes/sec, e.g. 1e6
	Windows   int     // rate window size
	MTU       int
}

func DefaultSpeedConfig() SpeedConfig {
	return SpeedConfig{
		InitSpeed: 4.5e6,
		MinSpeed:  1e6,
		Windows:   4,
		MTU:       DefaultMTU,
	}
}

// ─── UU Transport ───
// Manages the encrypted UDP connection to a single server, providing
// reliable ordered delivery with retransmit. Multiple sessions are
// multiplexed over one UDP socket.

type Transport struct {
	serverAddr *net.UDPAddr
	udpConn    net.Conn
	key        [32]byte

	// TX state
	txSeq      atomic.Uint32
	txBuffer   sync.Map // seq(uint32) -> *txEntry
	txReadySeq atomic.Uint32
	txTokens   chan struct{} // rate-limit tokens

	// RX state
	rxSeq    atomic.Uint32
	lastSeq  atomic.Int64 // -1 initially
	rxBuffer sync.Map     // seq(uint32) -> *rxEntry
	loseSeq  atomic.Uint32
	rxMu     sync.Mutex

	// Sessions
	sessions  sync.Map // sessionID(uint16) -> chan []byte
	sessionMu sync.Mutex

	// Config
	speed    SpeedConfig
	loss     LossConfig
	udpDelay atomic.Value // float64

	// State
	connected atomic.Bool
	stopCh    chan struct{}
	rxRawCh   chan rawPacket

	// Stats
	txBytes atomic.Uint64
	rxBytes atomic.Uint64
}

type txEntry struct {
	sessionID uint16
	msgType   byte
	payload   []byte
}

type rxEntry struct {
	sessionID uint16
	payload   []byte
}

type rawPacket struct {
	data []byte
	addr *net.UDPAddr
}

// NewTransport creates a new UU transport.
func NewTransport(serverAddr string, password string, speed SpeedConfig, loss LossConfig) (*Transport, error) {
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve server addr: %w", err)
	}
	t := &Transport{
		serverAddr: addr,
		key:        DeriveKey(password),
		speed:      speed,
		loss:       loss,
		stopCh:     make(chan struct{}),
		rxRawCh:    make(chan rawPacket, 4096),
		txTokens:   make(chan struct{}, speed.Windows*2),
	}
	t.lastSeq.Store(-1)
	delay := float64(speed.MTU) / speed.InitSpeed * 8.0
	t.udpDelay.Store(delay)

	// Pre-fill rate tokens
	for i := 0; i < speed.Windows; i++ {
		t.txTokens <- struct{}{}
	}
	return t, nil
}

// Connect establishes the UDP link to the server.
func (t *Transport) Connect(conn net.Conn) error {
	t.udpConn = conn
	if sb, ok := conn.(interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}); ok {
		setBufferWithFallback(sb, "Read", t.speed.MTU*1000000)
		setBufferWithFallback(sb, "Write", t.speed.MTU*1000000)
	}

	// Send connection request: header = "040588" + 0x00 + checksum
	nonce := makeNonce()
	header := append([]byte(ConnectPassword), 0x00)
	chk := blake2bChecksum1(header)
	header = append(header, chk)
	encHeader, _ := chacha20Xor(header, t.key[:], nonce)
	timestamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestamp, uint64(time.Now().UnixNano()))
	encPayload, _ := chacha20Xor(timestamp, t.key[:], nonce)
	packet := append(nonce, encHeader...)
	packet = append(packet, encPayload...)
	_, err := conn.Write(packet)
	if err != nil {
		return err
	}

	// Start background goroutines
	go t.recvLoop()
	go t.processLoop()
	go t.lossLoop()
	go t.speedLoop()
	go t.statusLoop()

	return nil
}

// Close shuts down the transport.
func (t *Transport) Close() error {
	select {
	case <-t.stopCh:
	default:
		close(t.stopCh)
	}
	t.connected.Store(false)
	if t.udpConn != nil {
		return t.udpConn.Close()
	}
	return nil
}

// IsConnected returns whether the transport has an active link.
func (t *Transport) IsConnected() bool {
	return t.connected.Load()
}

// ─── Session Management ───

// OpenSession registers a new session and returns its data channel.
func (t *Transport) OpenSession(sessionID uint16) chan []byte {
	ch := make(chan []byte, 20480)
	t.sessions.Store(sessionID, ch)
	return ch
}

// CloseSession removes a session.
func (t *Transport) CloseSession(sessionID uint16) {
	if v, ok := t.sessions.LoadAndDelete(sessionID); ok {
		ch := v.(chan []byte)
		select {
		case ch <- nil: // signal EOF
		default:
		}
	}
}

// ─── Send ───

// SendData sends a data payload for a session (msg_type=0x02), with rate limiting.
func (t *Transport) SendData(sessionID uint16, payload []byte) {
	t.sendMessage(sessionID, MsgData, payload, true)
}

// SendControl sends a control message (no rate limiting, seq=0).
func (t *Transport) SendControl(sessionID uint16, msgType byte, payload []byte) {
	t.sendMessage(sessionID, msgType, payload, false)
}

func (t *Transport) sendMessage(sessionID uint16, msgType byte, payload []byte, rateLimit bool) {
	if !t.connected.Load() {
		return
	}
	if msgType == MsgData {
		seq := t.txSeq.Add(1) - 1
		t.txBuffer.Store(seq, &txEntry{sessionID, msgType, payload})
		// Evict old entries
		if seq > MaxTXBuffer {
			t.txBuffer.Delete(t.txReadySeq.Load())
			t.txReadySeq.Add(1)
		}
		t.encryptAndSend(seq, sessionID, msgType, payload, rateLimit)
	} else if msgType == MsgResendR {
		// Resend response: payload contains list of 4-byte seqs
		for len(payload) >= 4 {
			loseSeq := binary.BigEndian.Uint32(payload[:4])
			payload = payload[4:]
			if v, ok := t.txBuffer.Load(loseSeq); ok {
				entry := v.(*txEntry)
				t.encryptAndSend(loseSeq, entry.sessionID, entry.msgType, entry.payload, false)
			}
		}
	} else {
		t.encryptAndSend(0, sessionID, msgType, payload, false)
	}
}

func (t *Transport) encryptAndSend(seq uint32, sessionID uint16, msgType byte, payload []byte, rateLimit bool) {
	if rateLimit {
		select {
		case <-t.txTokens:
		case <-t.stopCh:
			return
		}
	}
	nonce := makeNonce()
	header := make([]byte, HeaderPlainSize)
	binary.BigEndian.PutUint32(header[0:4], seq)
	binary.BigEndian.PutUint16(header[4:6], sessionID)
	header[6] = msgType

	chk := blake2bChecksum1(header)
	headerWithChk := append(header, chk)

	encHeader, _ := chacha20Xor(headerWithChk, t.key[:], nonce)
	encPayload, _ := chacha20Xor(payload, t.key[:], nonce)

	packet := make([]byte, 0, NonceSize+HeaderSize+len(encPayload))
	packet = append(packet, nonce...)
	packet = append(packet, encHeader...)
	packet = append(packet, encPayload...)

	t.udpConn.Write(packet)
	t.txBytes.Add(uint64(len(packet)))
}

// ─── Receive Loop ───

func (t *Transport) recvLoop() {
	buf := make([]byte, t.speed.MTU+64)
	for {
		select {
		case <-t.stopCh:
			return
		default:
		}
		t.udpConn.SetReadDeadline(time.Now().Add(15 * time.Second))
		n, err := t.udpConn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if t.connected.Load() {
					// Timeout while connected → reconnect
					t.connected.Store(false)
				}
				continue
			}
			continue
		}
		if n < NonceSize+HeaderSize {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		t.rxRawCh <- rawPacket{data: data, addr: t.serverAddr}
	}
}

func (t *Transport) processLoop() {
	for {
		select {
		case <-t.stopCh:
			return
		case raw := <-t.rxRawCh:
			t.processPacket(raw.data)
		}
	}
}

func (t *Transport) processPacket(data []byte) {
	t.rxBytes.Add(uint64(len(data)))

	nonce := data[:NonceSize]
	encHeader := data[NonceSize : NonceSize+HeaderSize]
	header, err := chacha20Xor(encHeader, t.key[:], nonce)
	if err != nil {
		return
	}

	chk := header[7]
	if chk != blake2bChecksum1(header[:7]) {
		return // checksum mismatch
	}

	seq := binary.BigEndian.Uint32(header[0:4])
	sessionID := binary.BigEndian.Uint16(header[4:6])
	msgType := header[6]

	var payload []byte
	if len(data) > NonceSize+HeaderSize {
		payload, _ = chacha20Xor(data[NonceSize+HeaderSize:], t.key[:], nonce)
	}

	switch msgType {
	case MsgStart: // Server confirmed link
		t.connected.Store(true)
		fmt.Printf("[Start server] %s\n", t.serverAddr)
		// Synchronize speed to server
		speedBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(speedBytes, uint32(t.speed.InitSpeed))
		t.SendControl(0, MsgAck, speedBytes)

	case MsgData:
		if !t.connected.Load() {
			return
		}
		rxSeq := t.rxSeq.Load()
		if seq >= rxSeq {
			t.rxBuffer.Store(seq, &rxEntry{sessionID, payload})
		}
		// Deliver in-order packets
		t.DeliverOrdered()
		// Update last_seq
		for {
			old := t.lastSeq.Load()
			if int64(seq) > old {
				if t.lastSeq.CompareAndSwap(old, int64(seq)) {
					break
				}
			} else {
				break
			}
		}

	case MsgClose:
		t.CloseSession(sessionID)

	case MsgResend: // Server requesting us to resend
		if len(payload) >= 4 {
			delay := t.udpDelay.Load().(float64)
			if len(payload)/4 >= 20 {
				delay = float64(t.speed.MTU) / t.speed.MinSpeed * 8.0
				t.udpDelay.Store(delay)
			}
			t.sendMessage(0, MsgResendR, payload, false)
		}
	}
}

func (t *Transport) DeliverOrdered() {
	t.rxMu.Lock()
	defer t.rxMu.Unlock()
	t.deliverOrderedLocked()
}

func (t *Transport) deliverOrderedLocked() {
	for {
		rxSeq := t.rxSeq.Load()
		v, ok := t.rxBuffer.Load(rxSeq)
		if !ok {
			break
		}
		entry := v.(*rxEntry)

		if ch, ok := t.sessions.Load(entry.sessionID); ok {
			dataCh := ch.(chan []byte)
			// 必須確保寫入成功，不能丟包
			select {
			case dataCh <- entry.payload:
				// 成功寫入後才刪除並移動序號
				t.rxBuffer.Delete(rxSeq)
				t.rxSeq.Store(rxSeq + 1)
			default:
				// 如果 Channel 滿了，暫時停止遞交，等待下一輪
				return
			}
		} else {
			// Session 已關閉，直接丟棄並跳過
			t.rxBuffer.Delete(rxSeq)
			t.rxSeq.Store(rxSeq + 1)
		}
	}
}

// ─── Loss Recovery Loop (matches handle_lose in uuclient.py) ───

func (t *Transport) lossLoop() {
	type lossEntry struct {
		firstSeen  time.Time
		lastSent   time.Time
		retryCount int
	}
	loseSeq := make(map[uint32]*lossEntry)

	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		rxSeq := t.rxSeq.Load()
		lastSeq := t.lastSeq.Load()
		delay := t.udpDelay.Load().(float64)

		if int64(rxSeq) < lastSeq {
			now := time.Now()
			grace := t.loss.RequestGrace
			if g := delay * 80; g > grace {
				grace = g
			}
			var resendList []byte
			for seq := rxSeq; int64(seq) < lastSeq; seq++ {
				if _, exists := t.rxBuffer.Load(seq); exists {
					continue
				}
				entry, tracked := loseSeq[seq]
				if !tracked {
					entry = &lossEntry{firstSeen: now}
					loseSeq[seq] = entry
				}
				retryCount := entry.retryCount
				if retryCount > t.loss.MaxRetry {
					retryCount = t.loss.MaxRetry
				}
				retryDelay := t.loss.RetryBase * float64(int(1)<<min(retryCount, 6))
				if retryDelay > t.loss.RetryMax {
					retryDelay = t.loss.RetryMax
				}
				if retryCount == 0 && now.Sub(entry.firstSeen).Seconds() < grace {
					continue
				}
				if retryCount > 0 && now.Sub(entry.lastSent).Seconds() < retryDelay {
					continue
				}
				// --- 關鍵修正：將 Skip 檢查移到重試次數檢查之前 ---
				if seq == rxSeq && now.Sub(entry.firstSeen).Seconds() >= t.loss.SkipAfter {
					t.rxMu.Lock()
					if t.rxSeq.Load() == seq {
						t.rxSeq.Store(seq + 1)
						delete(loseSeq, seq)
						t.deliverOrderedLocked()
					}
					t.rxMu.Unlock()
					rxSeq = t.rxSeq.Load()
					continue
				}

				if retryCount >= t.loss.MaxRetry {
					continue
				}
				// --- 結束修正 ---
				buf := make([]byte, 4)
				binary.BigEndian.PutUint32(buf, seq)
				resendList = append(resendList, buf...)
				entry.lastSent = now
				entry.retryCount++
				if len(resendList) >= t.loss.BatchSize*4 {
					break
				}
			}
			if len(resendList) > 0 {
				t.SendControl(0, MsgResend, resendList)
			}
			// Clean up resolved entries
			for seq := range loseSeq {
				if seq < t.rxSeq.Load() {
					delete(loseSeq, seq)
				} else if _, exists := t.rxBuffer.Load(seq); exists {
					delete(loseSeq, seq)
				}
			}
			sleepDur := delay * 20
			if sleepDur < 0.03 {
				sleepDur = 0.03
			}
			if sleepDur > 0.2 {
				sleepDur = 0.2
			}
			time.Sleep(time.Duration(sleepDur * float64(time.Second)))
		} else {
			sleepDur := delay * 10
			if sleepDur < 0.05 {
				sleepDur = 0.05
			}
			time.Sleep(time.Duration(sleepDur * float64(time.Second)))
		}
	}
}

// ─── Speed Control Loop (matches handle_speed_udptx) ───

func (t *Transport) speedLoop() {
	for {
		delay := t.udpDelay.Load().(float64)
		sleepDur := delay * float64(t.speed.Windows)
		time.Sleep(time.Duration(sleepDur * float64(time.Second)))

		select {
		case <-t.stopCh:
			return
		default:
		}

		// Refill tokens
		for i := 0; i < t.speed.Windows-len(t.txTokens); i++ {
			select {
			case t.txTokens <- struct{}{}:
			default:
			}
		}
	}
}

// ─── Status Loop (matches handle_status) ───

func (t *Transport) statusLoop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	count := 0
	lastTime := time.Now()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			count++
			if !t.connected.Load() {
				// Try reconnect
				t.reconnect()
			}
			if count >= 3 {
				elapsed := time.Since(lastTime).Seconds()
				txKB := float64(t.txBytes.Swap(0)) / elapsed / 1000
				rxKB := float64(t.rxBytes.Swap(0)) / elapsed / 1000
				fmt.Printf("\n[Status] TX=%.0f KB/s RX=%.0f KB/s\n", txKB, rxKB)
				lastTime = time.Now()

				// Reset delay to init speed
				delay := float64(t.speed.MTU) / t.speed.InitSpeed * 8.0
				t.udpDelay.Store(delay)

				// Heartbeat
				if t.connected.Load() {
					t.SendControl(0, MsgData, makeRandomPadding())
				}
				count = 0
			}
		}
	}
}

func (t *Transport) reconnect() {
	if t.udpConn == nil {
		return
	}
	nonce := makeNonce()
	header := append([]byte(ConnectPassword), 0x00)
	chk := blake2bChecksum1(header)
	header = append(header, chk)
	encHeader, _ := chacha20Xor(header, t.key[:], nonce)
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(time.Now().UnixNano()))
	encPayload, _ := chacha20Xor(ts, t.key[:], nonce)
	packet := append(nonce, encHeader...)
	packet = append(packet, encPayload...)
	t.udpConn.Write(packet)
}

// ─── Helpers ───

func makeNonce() []byte {
	nonce := make([]byte, NonceSize)
	cryptorand.Read(nonce)
	return nonce
}

func makeRandomPadding() []byte {
	n := 64 + rand.Intn(1188-64)
	b := make([]byte, n)
	cryptorand.Read(b)
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func setBufferWithFallback(conn interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}, name string, initialSize int) {
	sizes := []int{initialSize, 16 * 1024 * 1024, 8 * 1024 * 1024, 4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024}
	var err error
	for _, size := range sizes {
		if name == "Read" {
			err = conn.SetReadBuffer(size)
		} else {
			err = conn.SetWriteBuffer(size)
		}
		if err == nil {
			if size != initialSize {
				fmt.Printf("[Transport] Warning: failed to set UDP %s buffer to %d, successfully fallback to %d bytes (OS limits may apply)\n", name, initialSize, size)
			}
			return
		}
	}
	fmt.Printf("[Transport] Warning: failed to set UDP %s buffer: %v\n", name, err)
}
