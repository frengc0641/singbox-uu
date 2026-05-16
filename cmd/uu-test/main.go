// Standalone test: runs the UU client as a local SOCKS5 proxy
// (like uuclient.py) without needing sing-box.
//
// Usage: go run . -server 45.207.206.163:8888 -listen 127.0.0.1:1080
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"

	uu "singbox-uu/protocol/uu"
)

var (
	serverAddr = flag.String("server", "45.207.206.163:8888", "UU server address")
	listenAddr = flag.String("listen", "127.0.0.1:1080", "Local SOCKS5 listen address")
	password   = flag.String("password", "ch0641ng", "UU password")
	speedMbps  = flag.Float64("speed", 4.5, "Init speed in Mbps")
)

func main() {
	flag.Parse()
	fmt.Printf("UU Client starting...\n")
	fmt.Printf("  Server:  %s\n", *serverAddr)
	fmt.Printf("  Listen:  %s\n", *listenAddr)

	transport, err := uu.NewTransport(*serverAddr, *password, uu.SpeedConfig{
		InitSpeed: *speedMbps * 1e6,
		MinSpeed:  1e6,
		Windows:   4,
		MTU:       uu.DefaultMTU,
	}, uu.DefaultLossConfig())
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if err := transport.Connect(); err != nil {
		fmt.Printf("Connect error: %v\n", err)
		return
	}
	fmt.Println("Waiting for server link...")
	for i := 0; i < 100; i++ {
		if transport.IsConnected() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !transport.IsConnected() {
		fmt.Println("Failed to connect to server")
		return
	}
	fmt.Println("Connected! Starting SOCKS5 proxy...")

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		fmt.Printf("Listen error: %v\n", err)
		return
	}
	defer listener.Close()
	fmt.Printf("SOCKS5 proxy listening on %s\n", *listenAddr)

	nextSID := uint16(rand.Intn(60000) + 1)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		sid := nextSID
		nextSID++
		if nextSID > 65000 {
			nextSID = 1
		}
		go handleSOCKS5(conn, transport, sid)
	}
}

func handleSOCKS5(conn net.Conn, transport *uu.Transport, sessionID uint16) {
	defer conn.Close()

	// SOCKS5 handshake
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 1 || buf[0] != 5 {
		return
	}
	conn.Write([]byte{0x05, 0x00}) // No auth

	// Read connect request
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}
	addrType := buf[3]
	var address string
	var port uint16
	var connData []byte

	switch addrType {
	case 1: // IPv4
		address = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		port = binary.BigEndian.Uint16(buf[8:10])
		connData = make([]byte, 0, 7)
		connData = append(connData, 0x01)
		connData = append(connData, buf[4:8]...)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, port)
		connData = append(connData, portBuf...)
	case 3: // Domain
		domLen := buf[4]
		address = string(buf[5 : 5+domLen])
		port = binary.BigEndian.Uint16(buf[5+domLen : 7+domLen])
		connData = make([]byte, 0, 1+1+int(domLen)+2)
		connData = append(connData, 0x03)
		connData = append(connData, domLen)
		connData = append(connData, buf[5:5+domLen]...)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, port)
		connData = append(connData, portBuf...)
	default:
		return
	}

	fmt.Printf("[%d]\t[Open] %s:%d\n", sessionID, address, port)

	dataCh := transport.OpenSession(sessionID)
	defer transport.CloseSession(sessionID)

	// Send new session
	transport.SendControl(sessionID, uu.MsgNew, connData)

	// Wait for server response
	select {
	case resp := <-dataCh:
		if resp == nil || len(resp) < 2 || resp[1] != 0x00 {
			fmt.Printf("[%d]\t[Connect failed]\n", sessionID)
			return
		}
	case <-time.After(5 * time.Second):
		fmt.Printf("[%d]\t[Connect timeout]\n", sessionID)
		return
	}

	// Tell browser: connection established
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Bidirectional relay
	done := make(chan struct{}, 2)

	// Browser → Server
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, uu.DefaultMTU)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				transport.SendControl(sessionID, uu.MsgClose, makeRandomPadding())
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			transport.SendData(sessionID, data)
		}
	}()

	// Server → Browser
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			payload, ok := <-dataCh
			if !ok || payload == nil {
				return
			}
			_, err := conn.Write(payload)
			if err != nil {
				transport.SendControl(sessionID, uu.MsgClose, makeRandomPadding())
				return
			}
		}
	}()

	<-done
	fmt.Printf("[%d]\t[Close]\n", sessionID)
}

func makeRandomPadding() []byte {
	n := 64 + rand.Intn(1188-64)
	b := make([]byte, n)
	io.ReadFull(rand.New(rand.NewSource(time.Now().UnixNano())), b)
	return b
}
