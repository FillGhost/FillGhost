package fillghost

import (
	"encoding/binary"
	"fmt"
	"log"
)

// TLSRecordEncryptor is an abstract interface for encrypting raw payload data
// into a complete and valid TLS Application Data record.
//
// In a production environment, an implementation of this interface must deeply integrate
// with the proxy server's underlying TLS stack to access the active TLS session's
// cryptographic context (e.g., session keys, nonce state, sequence numbers).
// The standard Go `crypto/tls` library does not expose APIs for external application code
// to directly encrypt arbitrary data using established TLS session keys. Data is encrypted
// and encapsulated into TLS records only when written to a `*tls.Conn` object.
//
// Therefore, a true implementation would likely involve:
// 1. Hooking into a lower-level network writer that sits *below* `tls.Conn.Write()`,
//    but *above* `net.Conn.Write()`, allowing injection of pre-formed TLS records.
// 2. Implementing a custom TLS stack (highly complex).
// 3. Using FFI to interface with a C TLS library (e.g., OpenSSL) that provides such APIs.
//
// This interface defines how such an encryptor *would* be called if available.
type TLSRecordEncryptor interface {
	// EncryptApplicationData encrypts the given raw payload using the current TLS session parameters
	// and encapsulates it into a complete, valid TLS Application Data record.
	//
	// tlsVersion: The 2-byte TLS version negotiated for the current connection
	//             (e.g., [0x03, 0x01] for TLS 1.0, [0x03, 0x02] for TLS 1.1,
	//             [0x03, 0x03] for TLS 1.2, [0x03, 0x04] for TLS 1.3).
	// recordType: The TLS record type (e.g., 0x17 for Application Data, which FillGhost uses).
	// rawPayload: The raw byte data to be encrypted (e.g., random data for FillGhost packets).
	//
	// Returns: A byte slice representing the complete TLS Application Data record,
	//          encrypted and ready for network transmission.
	//          Returns an error if encryption or record construction fails.
	EncryptApplicationData(tlsVersion []byte, recordType byte, rawPayload []byte) ([]byte, error)

	// SetTLSContext is a conceptual method for a real TLSRecordEncryptor implementation
	// to receive the necessary TLS session context (e.g., negotiated TLS version,
	// cipher suite, and the derived master secret or session keys).
	// This method illustrates how dynamic TLS-specific parameters from an active
	// `*tls.Conn` would be provided to the encryptor.
	SetTLSContext(tlsVersion []byte, cipherSuiteID uint16, masterSecret []byte) error
}

// MockTLSRecordEncryptor is a mock implementation of the TLSRecordEncryptor interface.
//
// WARNING: This implementation does NOT perform actual cryptographic TLS record encryption
// or MAC calculation. It only constructs a valid-looking TLS record header
// and appends the raw payload without encryption.
//
// For production, this mock MUST be replaced by a real implementation that
// integrates with a TLS stack capable of providing the required low-level encryption.
type MockTLSRecordEncryptor struct {
	sessionID     string
	currentTLSVer []byte
	currentCipher uint16
	// In a real implementation, you would store actual session keys, IVs, sequence numbers, etc.
}

// NewMockTLSRecordEncryptor creates a new instance of MockTLSRecordEncryptor.
func NewMockTLSRecordEncryptor(sessionID string) *MockTLSRecordEncryptor {
	log.Printf("fillghost: WARNING: Using MockTLSRecordEncryptor for session: %s.", sessionID)
	log.Println("fillghost: This implementation does NOT perform actual TLS record encryption.")
	log.Println("fillghost: For production, replace this with a real TLS stack integration.")
	return &MockTLSRecordEncryptor{sessionID: sessionID}
}

// SetTLSContext conceptually sets the TLS context for the mock.
// In a real scenario, this would be crucial for establishing the encryption parameters.
func (m *MockTLSRecordEncryptor) SetTLSContext(tlsVersion []byte, cipherSuiteID uint16, masterSecret []byte) error {
	if len(tlsVersion) != 2 {
		return fmt.Errorf("fillghost: invalid TLS version byte slice length: %d, expected 2", len(tlsVersion))
	}
	m.currentTLSVer = tlsVersion
	m.currentCipher = cipherSuiteID
	// In a real implementation, masterSecret would be used to derive session keys and initialize ciphers.
	log.Printf("fillghost: MockTLSRecordEncryptor for session %s received TLS context: Version %x, CipherSuite %x",
		m.sessionID, m.currentTLSVer, m.currentCipher)
	return nil
}

// EncryptApplicationData simulates TLS record encryption by prepending a valid-looking
// TLS record header to the raw payload. This method does NOT apply actual encryption or MAC.
func (m *MockTLSRecordEncryptor) EncryptApplicationData(tlsVersion []byte, recordType byte, rawPayload []byte) ([]byte, error) {
	if len(tlsVersion) != 2 {
		return nil, fmt.Errorf("fillghost: encryptor: invalid TLS version byte slice length: %d, expected 2", len(tlsVersion))
	}
	if recordType != 0x17 { // FillGhost specifically targets Application Data (0x17)
		return nil, fmt.Errorf("fillghost: encryptor: unsupported record type %x for FillGhost, must be 0x17 (Application Data)", recordType)
	}

	// The `Length` field in the TLS record header is 2 bytes, representing the length
	// of the *encrypted* payload. The maximum practical TLS record payload length
	// is 2^14 (16384 bytes).
	encryptedPayloadLength := len(rawPayload) // In mock, raw_payload_len == encrypted_payload_len
	if encryptedPayloadLength > 0x3FFF {
		return nil, fmt.Errorf("fillghost: encryptor: raw payload length %d exceeds max practical TLS record payload length (16384 bytes)", encryptedPayloadLength)
	}

	tlsLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(tlsLengthBytes, uint16(encryptedPayloadLength))

	// Assemble the mock TLS record: Type (1B) + Version (2B) + Length (2B) + (simulated) Encrypted Payload
	record := make([]byte, 0, 1+2+2+len(rawPayload))
	record = append(record, recordType)       // Record Type (e.g., 0x17)
	record = append(record, tlsVersion...)    // TLS Version (e.g., 0x0304)
	record = append(record, tlsLengthBytes...) // Encrypted Length
	record = append(record, rawPayload...)    // "Encrypted" payload (raw data in mock)

	return record, nil
}
