package fillghost

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// PacketGenerator provides utilities for generating random data and lengths required for FillGhost packets.
type PacketGenerator struct{}

// NewPacketGenerator creates a new instance of PacketGenerator.
func NewPacketGenerator() *PacketGenerator {
	return &PacketGenerator{}
}

// GenerateRandomBytes generates a cryptographically secure random byte slice of the specified length.
// It returns an error if the length is negative or if random byte generation fails.
func (pg *PacketGenerator) GenerateRandomBytes(length int) ([]byte, error) {
	if length < 0 {
		return nil, fmt.Errorf("fillghost: length must be a non-negative integer")
	}
	b := make([]byte, length)
	_, err := rand.Read(b) // Use crypto/rand for cryptographic security
	if err != nil {
		return nil, fmt.Errorf("fillghost: failed to generate random bytes: %w", err)
	}
	return b, nil
}

// GetRandomFillGhostLength generates a random integer length for a FillGhost packet's payload.
// The returned length will be used for the encrypted payload of a TLS Application Data record.
// The externally visible TLS record length will include this payload length plus TLS overheads (MAC, padding).
// It returns an error if minLen or maxLen are invalid.
func (pg *PacketGenerator) GetRandomFillGhostLength(minLen, maxLen int) (int, error) {
	if minLen < 0 || maxLen < 0 || minLen > maxLen {
		return 0, fmt.Errorf("fillghost: minLen and maxLen must be non-negative integers, and minLen <= maxLen")
	}
	if minLen == maxLen {
		return minLen, nil
	}
	// Use math/big.Int for generating cryptographically secure random numbers within a range.
	diff := big.NewInt(int64(maxLen - minLen + 1))
	n, err := rand.Int(rand.Reader, diff)
	if err != nil {
		return 0, fmt.Errorf("fillghost: failed to generate random length: %w", err)
	}
	return int(n.Int64()) + minLen, nil
}
