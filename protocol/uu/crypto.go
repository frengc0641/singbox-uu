// Package uu implements the UU custom UDP proxy protocol.
// This file handles ChaCha20 encryption and Blake2b checksum,
// matching the wire format of uuserver.py / uuclient.py.
package uu

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/blake2b"
)

// DeriveKey derives a 32-byte ChaCha20 key from a password string using SHA-256.
// Matches Python: hashlib.sha256('ch0641ng'.encode()).digest()
func DeriveKey(password string) [32]byte {
	return sha256.Sum256([]byte(password))
}

// chacha20Xor encrypts/decrypts data using ChaCha20 (IETF variant with 8-byte nonce).
// Uses a 32-byte key and 8-byte nonce, matching libsodium's crypto_stream_chacha20_xor.
// The 8-byte nonce is zero-padded to 12 bytes for the Go chacha20 IETF implementation,
// with a zero initial counter — this matches libsodium's original chacha20 (not IETF).
func chacha20Xor(data, key, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	if len(nonce) != 8 {
		return nil, fmt.Errorf("nonce must be 8 bytes, got %d", len(nonce))
	}

	// libsodium crypto_stream_chacha20_xor uses the original ChaCha20 with 8-byte nonce.
	// Go's chacha20.NewUnauthenticatedCipher with a 24-byte nonce = XChaCha20,
	// but we need original ChaCha20. We'll use the chacha20 package with HChaCha20 trick
	// or simply pad the nonce.
	//
	// Actually, golang.org/x/crypto/chacha20 supports:
	//   - 24-byte nonce (XChaCha20)
	//   - 12-byte nonce (IETF ChaCha20)
	// But libsodium's crypto_stream_chacha20_xor uses original 8-byte nonce (counter=0).
	//
	// The original ChaCha20 has a 8-byte nonce + 8-byte counter.
	// The IETF variant has a 12-byte nonce + 4-byte counter.
	// They are NOT compatible.
	//
	// We use the chacha20 package's low-level SetCounter approach:
	// Treat the 8-byte nonce as: first 4 bytes = extra counter, last 4+8 = 12-byte IETF nonce?
	// No — we need to match libsodium exactly.
	//
	// libsodium's crypto_stream_chacha20_xor(c, m, mlen, n, k):
	//   n = 8-byte nonce, internal counter starts at 0
	//   State: key(32) | counter(8, starting 0) | nonce(8)
	//
	// Go chacha20 IETF: key(32) | counter(4) | nonce(12)
	//   State layout differs.
	//
	// For compatibility, we construct a 12-byte nonce = [0,0,0,0] + nonce[0:8]
	// and set counter = 0. This maps to the same initial state as libsodium's
	// original chacha20 when counter starts at 0.
	ietfNonce := make([]byte, 12)
	copy(ietfNonce[4:], nonce) // pad 4 zero bytes in front

	cipher, err := chacha20.NewUnauthenticatedCipher(key, ietfNonce)
	if err != nil {
		return nil, err
	}
	cipher.SetCounter(0)

	out := make([]byte, len(data))
	cipher.XORKeyStream(out, data)
	return out, nil
}

// blake2bChecksum1 computes a 1-byte Blake2b digest, matching Python:
// hashlib.blake2b(data, digest_size=1).digest()
func blake2bChecksum1(data []byte) byte {
	// blake2b with 1-byte digest — use the unkeyed variant
	h, _ := blake2b.New(1, nil) // 1-byte output, no key
	h.Write(data)
	sum := h.Sum(nil)
	return sum[0]
}
