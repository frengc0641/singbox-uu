// Package uu provides the sing-box outbound integration for the UU protocol.
// This file implements the sing-box adapter.Outbound interface, bridging
// sing-box's connection model to the UU custom UDP transport.
//
// To use in sing-box config:
//
//	{
//	  "outbounds": [{
//	    "type": "uu",
//	    "tag": "uu-out",
//	    "server": "45.207.206.163",
//	    "server_port": 8888,
//	    "password": "ch0641ng",
//	    "init_speed_mbps": 4.5,
//	    "min_speed_mbps": 1.0
//	  }]
//	}
package uu

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ─── sing-box type constant ───

const TypeUU = "uu"

// ─── Config Options (for sing-box JSON config) ───

type UUOutboundOptions struct {
	option.DialerOptions
	option.ServerOptions
	Password      string  `json:"password,omitempty"`
	InitSpeedMbps float64 `json:"init_speed_mbps,omitempty"`
	MinSpeedMbps  float64 `json:"min_speed_mbps,omitempty"`
}

// ─── Registration ───

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[UUOutboundOptions](registry, TypeUU, NewOutbound)
}

// ─── Outbound Implementation ───

var _ adapter.Outbound = (*UUOutbound)(nil)

type UUOutbound struct {
	outbound.Adapter
	logger    logger.ContextLogger
	dialer    N.Dialer
	transport *Transport
	server    string
	port      uint16
	password  string
	speed     SpeedConfig
	loss      LossConfig
	nextSID   atomic.Uint32
	startOnce sync.Once
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger,
	tag string, options UUOutboundOptions) (adapter.Outbound, error) {

	password := options.Password
	if password == "" {
		password = DefaultPassword
	}
	initSpeed := options.InitSpeedMbps
	if initSpeed <= 0 {
		initSpeed = 4.5
	}
	minSpeed := options.MinSpeedMbps
	if minSpeed <= 0 {
		minSpeed = 1.0
	}

	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	o := &UUOutbound{
		Adapter: outbound.NewAdapterWithDialerOptions(TypeUU, tag,
			[]string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		logger:   logger,
		dialer:   outboundDialer,
		server:   options.Server,
		port:     options.ServerPort,
		password: password,
		speed: SpeedConfig{
			InitSpeed: initSpeed * 1e6,
			MinSpeed:  minSpeed * 1e6,
			Windows:   4,
			MTU:       DefaultMTU,
		},
		loss: DefaultLossConfig(),
	}
	// Start session IDs from a random offset
	o.nextSID.Store(uint32(rand.Intn(60000) + 1))
	return o, nil
}

// ensureTransport lazily creates and connects the UDP transport.
func (o *UUOutbound) ensureTransport(ctx context.Context) error {
	var err error
	o.startOnce.Do(func() {
		serverAddr := fmt.Sprintf("%s:%d", o.server, o.port)

		// 關鍵修復：使用 sing-box 的 Dialer 來建立 UDP 連線，這樣才能被 Android VpnService protect()
		dialAddr := M.ParseSocksaddrHostPort(o.server, o.port)
		conn, dialErr := o.dialer.DialContext(ctx, N.NetworkUDP, dialAddr)
		if dialErr != nil {
			err = dialErr
			return
		}

		o.transport, err = NewTransport(serverAddr, o.password, o.speed, o.loss)
		if err != nil {
			conn.Close()
			return
		}
		err = o.transport.Connect(conn)
		if err != nil {
			conn.Close()
		}
	})
	if err != nil {
		o.startOnce = sync.Once{} // Allow retry
	}
	return err
}

func (o *UUOutbound) allocSessionID() uint16 {
	return uint16(o.nextSID.Add(1) % 65500)
}

// ─── DialContext (sing-box calls this for each new TCP connection) ───
// This is the main entry point. sing-box passes us a destination address,
// and we return a net.Conn that transparently tunnels through UU protocol.

func (o *UUOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination

	if N.NetworkName(network) != N.NetworkTCP {
		return nil, fmt.Errorf("uu: only TCP is supported, got %s", network)
	}

	o.logger.InfoContext(ctx, "outbound connection to ", destination)

	if err := o.ensureTransport(ctx); err != nil {
		return nil, fmt.Errorf("uu: transport connect failed: %w", err)
	}

	// Wait for link to be established
	for i := 0; i < 50; i++ { // 5 seconds max
		if o.transport.IsConnected() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !o.transport.IsConnected() {
		return nil, fmt.Errorf("uu: server not connected after timeout")
	}

	sessionID := o.allocSessionID()
	dataCh := o.transport.OpenSession(sessionID)

	// Build SOCKS5-style connect request
	// Matches uuclient.py handle_browser(): conn_data format
	var connData []byte
	if destination.IsIPv4() {
		ip := destination.Addr.As4()
		connData = make([]byte, 0, 1+4+2)
		connData = append(connData, 0x01) // IPv4 type
		connData = append(connData, ip[:]...)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, destination.Port)
		connData = append(connData, portBuf...)
	} else if destination.IsDomain() {
		domainBytes := []byte(destination.Fqdn)
		connData = make([]byte, 0, 1+1+len(domainBytes)+2)
		connData = append(connData, 0x03) // domain type
		connData = append(connData, byte(len(domainBytes)))
		connData = append(connData, domainBytes...)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, destination.Port)
		connData = append(connData, portBuf...)
	} else {
		// IPv6 is not natively supported by the custom SOCKS5 protocol handshake
		o.transport.CloseSession(sessionID)
		return nil, fmt.Errorf("uu: IPv6 is not supported")
	}

	// Send new session request (msg_type=0x01)
	o.transport.SendControl(sessionID, MsgNew, connData)

	// Wait for server response
	select {
	case resp := <-dataCh:
		if resp == nil || len(resp) < 2 || resp[1] != 0x00 {
			o.transport.CloseSession(sessionID)
			return nil, fmt.Errorf("uu: remote connection failed")
		}
	case <-time.After(5 * time.Second):
		o.transport.CloseSession(sessionID)
		return nil, fmt.Errorf("uu: connect timeout")
	case <-ctx.Done():
		o.transport.CloseSession(sessionID)
		return nil, ctx.Err()
	}

	// Return a net.Conn that wraps the UU session
	return &uuConn{
		transport: o.transport,
		sessionID: sessionID,
		dataCh:    dataCh,
		readBuf:   nil,
	}, nil
}

// ListenPacket — UDP proxy not supported, only TCP tunneling.
func (o *UUOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("uu: UDP proxy not supported")
}

// ─── uuConn implements net.Conn over a UU session ───

type uuConn struct {
	transport *Transport
	sessionID uint16
	dataCh    chan []byte
	readBuf   []byte // leftover from partial read
	closed    atomic.Bool
}

func (c *uuConn) Read(b []byte) (int, error) {
	// First, drain any leftover buffer
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Block waiting for data from server
	data, ok := <-c.dataCh
	if !ok || data == nil {
		return 0, io.EOF
	}

	// --- 新增：讀取後立刻觸發遞交機制，填補緩衝區空位 ---
	c.transport.DeliverOrdered()
	// ----------------------------------------------
	n := copy(b, data)
	if n < len(data) {
		c.readBuf = data[n:]
	}
	return n, nil
}

func (c *uuConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	// Split into MTU-sized chunks
	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > DefaultMTU {
			chunk = b[:DefaultMTU]
		}
		c.transport.SendData(c.sessionID, chunk)
		b = b[len(chunk):]
		total += len(chunk)
	}
	return total, nil
}

func (c *uuConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		padding := make([]byte, 64+rand.Intn(1188-64))
		rand.Read(padding)
		c.transport.SendControl(c.sessionID, MsgClose, padding)
		c.transport.CloseSession(c.sessionID)
	}
	return nil
}

func (c *uuConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *uuConn) RemoteAddr() net.Addr {
	return c.transport.serverAddr
}

func (c *uuConn) SetDeadline(t time.Time) error      { return nil }
func (c *uuConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *uuConn) SetWriteDeadline(t time.Time) error { return nil }
