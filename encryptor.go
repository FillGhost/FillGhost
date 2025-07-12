package fillghost

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync/atomic"
)

// TLSCipherMode is an enum representing the cipher mode.
type TLSCipherMode int

const (
	ModeUnknown TLSCipherMode = iota
	ModeStream      // e.g. RC4
	ModeCBC         // e.g. AES-CBC, 3DES-CBC
	ModeGCM         // AEAD GCM
	ModeCCM         // AEAD CCM
	ModeCHACHA20POLY1305
)

func (m TLSCipherMode) String() string {
	switch m {
	case ModeStream:
		return "STREAM"
	case ModeCBC:
		return "CBC"
	case ModeGCM:
		return "GCM"
	case ModeCCM:
		return "CCM"
	case ModeCHACHA20POLY1305:
		return "CHACHA20-POLY1305"
	default:
		return "UNKNOWN"
	}
}

// TLSRecordEncryptor defines the interface for TLS record encryption.
type TLSRecordEncryptor interface {
	// EncryptApplicationData encrypts and encapsulates the raw payload
	// as a TLS Application Data record according to context and mode.
	EncryptApplicationData(tlsVersion []byte, recordType byte, rawPayload []byte) ([]byte, error)
	// SetTLSContext configures the cipher, keys, IV, and mode.
	SetTLSContext(ctx *TLSContext) error
	// CipherMode returns the current encryption mode.
	CipherMode() TLSCipherMode
}

// TLSContext holds all negotiated parameters needed for record encryption.
type TLSContext struct {
	TLSVersion      []byte
	CipherSuiteID   uint16
	MasterSecret    []byte
	ClientRandom    []byte
	ServerRandom    []byte
	IsClient        bool // true: client write, false: server write
	// Optionally for AEAD
	ExplicitNonceLen int
}

// Implementation for all supported modes:
type genericTLSRecordEncryptor struct {
	ctx      *TLSContext
	mode     TLSCipherMode
	aead     cipher.AEAD
	stream   cipher.Stream
	block    cipher.Block
	macKey   []byte
	iv       []byte
	seqNum   uint64
	macHash  func() hash.Hash
	keyLen   int
	macLen   int
	ivLen    int
}

func NewTLSRecordEncryptor() TLSRecordEncryptor {
	return &genericTLSRecordEncryptor{}
}

func (e *genericTLSRecordEncryptor) CipherMode() TLSCipherMode {
	return e.mode
}

// SetTLSContext: negotiates and initializes all keys/IVs according to the RFCs.
func (e *genericTLSRecordEncryptor) SetTLSContext(ctx *TLSContext) error {
	e.ctx = ctx

	// Cipher suite selection (partial, demo, expand as needed)
	switch ctx.CipherSuiteID {
	case 0x009C: // TLS_RSA_WITH_AES_128_GCM_SHA256 (RFC 5288 AEAD GCM)
		e.mode = ModeGCM
		keyLen := 16
		ivLen := 4
		macLen := 0
		prk, err := prfSHA256(ctx.MasterSecret, "key expansion", append(ctx.ServerRandom, ctx.ClientRandom...), 2*keyLen+2*ivLen)
		if err != nil {
			return err
		}
		var clientWriteKey, serverWriteKey, clientWriteIV, serverWriteIV []byte
		clientWriteKey = prk[0:keyLen]
		serverWriteKey = prk[keyLen : 2*keyLen]
		clientWriteIV = prk[2*keyLen : 2*keyLen+ivLen]
		serverWriteIV = prk[2*keyLen+ivLen:]
		var writeKey, writeIV []byte
		if ctx.IsClient {
			writeKey = clientWriteKey
			writeIV = clientWriteIV
		} else {
			writeKey = serverWriteKey
			writeIV = serverWriteIV
		}
		block, err := aes.NewCipher(writeKey)
		if err != nil {
			return err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		e.aead = aead
		e.iv = writeIV
		e.keyLen = keyLen
		e.ivLen = ivLen
		e.macLen = macLen
		return nil

	case 0x002F: // TLS_RSA_WITH_AES_128_CBC_SHA (RFC 5246 CBC + HMAC-SHA1)
		e.mode = ModeCBC
		keyLen := 16
		macLen := 20
		ivLen := 16
		prk, err := prfSHA1(ctx.MasterSecret, "key expansion", append(ctx.ServerRandom, ctx.ClientRandom...), 2*macLen+2*keyLen+2*ivLen)
		if err != nil {
			return err
		}
		clientMAC, serverMAC := prk[0:macLen], prk[macLen:2*macLen]
		clientWriteKey, serverWriteKey := prk[2*macLen:2*macLen+keyLen], prk[2*macLen+keyLen:2*macLen+2*keyLen]
		clientWriteIV, serverWriteIV := prk[2*macLen+2*keyLen:2*macLen+2*keyLen+ivLen], prk[2*macLen+2*keyLen+ivLen:]
		var writeKey, writeIV, macKey []byte
		if ctx.IsClient {
			writeKey = clientWriteKey
			writeIV = clientWriteIV
			macKey = clientMAC
		} else {
			writeKey = serverWriteKey
			writeIV = serverWriteIV
			macKey = serverMAC
		}
		block, err := aes.NewCipher(writeKey)
		if err != nil {
			return err
		}
		e.block = block
		e.iv = writeIV
		e.macKey = macKey
		e.macLen = macLen
		e.keyLen = keyLen
		e.ivLen = ivLen
		e.macHash = sha1.New
		return nil

	case 0x000A: // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		e.mode = ModeCBC
		keyLen := 24
		macLen := 20
		ivLen := 8
		prk, err := prfSHA1(ctx.MasterSecret, "key expansion", append(ctx.ServerRandom, ctx.ClientRandom...), 2*macLen+2*keyLen+2*ivLen)
		if err != nil {
			return err
		}
		clientMAC, serverMAC := prk[0:macLen], prk[macLen:2*macLen]
		clientWriteKey, serverWriteKey := prk[2*macLen:2*macLen+keyLen], prk[2*macLen+keyLen:2*macLen+2*keyLen]
		clientWriteIV, serverWriteIV := prk[2*macLen+2*keyLen:2*macLen+2*keyLen+ivLen], prk[2*macLen+2*keyLen+ivLen:]
		var writeKey, writeIV, macKey []byte
		if ctx.IsClient {
			writeKey = clientWriteKey
			writeIV = clientWriteIV
			macKey = clientMAC
		} else {
			writeKey = serverWriteKey
			writeIV = serverWriteIV
			macKey = serverMAC
		}
		block, err := des.NewTripleDESCipher(writeKey)
		if err != nil {
			return err
		}
		e.block = block
		e.iv = writeIV
		e.macKey = macKey
		e.macLen = macLen
		e.keyLen = keyLen
		e.ivLen = ivLen
		e.macHash = sha1.New
		return nil

	case 0xC02F: // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		// Same as above GCM, use SHA256
		e.mode = ModeGCM
		keyLen := 16
		ivLen := 4
		macLen := 0
		prk, err := prfSHA256(ctx.MasterSecret, "key expansion", append(ctx.ServerRandom, ctx.ClientRandom...), 2*keyLen+2*ivLen)
		if err != nil {
			return err
		}
		var clientWriteKey, serverWriteKey, clientWriteIV, serverWriteIV []byte
		clientWriteKey = prk[0:keyLen]
		serverWriteKey = prk[keyLen : 2*keyLen]
		clientWriteIV = prk[2*keyLen : 2*keyLen+ivLen]
		serverWriteIV = prk[2*keyLen+ivLen:]
		var writeKey, writeIV []byte
		if ctx.IsClient {
			writeKey = clientWriteKey
			writeIV = clientWriteIV
		} else {
			writeKey = serverWriteKey
			writeIV = serverWriteIV
		}
		block, err := aes.NewCipher(writeKey)
		if err != nil {
			return err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		e.aead = aead
		e.iv = writeIV
		e.keyLen = keyLen
		e.ivLen = ivLen
		e.macLen = macLen
		return nil

	case 0x1301: // TLS_AES_128_GCM_SHA256 (TLS 1.3)
		e.mode = ModeGCM
		// For TLS 1.3, key schedule is different and not shown here.
		return errors.New("TLS 1.3 AEAD key schedule not implemented in this demo")

	default:
		return fmt.Errorf("unsupported cipher suite: %#x", ctx.CipherSuiteID)
	}
}

// EncryptApplicationData: auto-selects by mode.
func (e *genericTLSRecordEncryptor) EncryptApplicationData(tlsVersion []byte, recordType byte, rawPayload []byte) ([]byte, error) {
	if e.ctx == nil {
		return nil, errors.New("TLS context not set")
	}
	if len(tlsVersion) != 2 {
		return nil, errors.New("invalid TLS version bytes")
	}
	if recordType != 0x17 {
		return nil, fmt.Errorf("only Application Data (0x17) supported, got %x", recordType)
	}
	if len(rawPayload) > 0x3FFF {
		return nil, fmt.Errorf("payload exceeds max TLS record size (16384)")
	}
	switch e.mode {
	case ModeGCM:
		return e.encryptGCM(tlsVersion, recordType, rawPayload)
	case ModeCBC:
		return e.encryptCBC(tlsVersion, recordType, rawPayload)
	default:
		return nil, fmt.Errorf("mode %v not implemented", e.mode)
	}
}

// AEAD (GCM) record encryption, see RFC 5288 for AAD/IV layout.
func (e *genericTLSRecordEncryptor) encryptGCM(tlsVersion []byte, recordType byte, rawPayload []byte) ([]byte, error) {
	seq := atomic.AddUint64(&e.seqNum, 1) - 1
	nonce := make([]byte, len(e.iv)+8)
	copy(nonce, e.iv)
	binary.BigEndian.PutUint64(nonce[len(e.iv):], seq)

	// AAD: seq_num(8) || type(1) || version(2) || length(2)
	additional := make([]byte, 13)
	binary.BigEndian.PutUint64(additional, seq)
	additional[8] = recordType
	copy(additional[9:11], tlsVersion)
	binary.BigEndian.PutUint16(additional[11:13], uint16(len(rawPayload)))

	ciphertext := e.aead.Seal(nil, nonce, rawPayload, additional)
	length := len(ciphertext)
	record := make([]byte, 0, 1+2+2+length)
	record = append(record, recordType)
	record = append(record, tlsVersion...)
	record = append(record, byte(length>>8), byte(length))
	record = append(record, ciphertext...)
	return record, nil
}

// CBC mode with HMAC (MAC-then-encrypt, RFC 5246).
func (e *genericTLSRecordEncryptor) encryptCBC(tlsVersion []byte, recordType byte, rawPayload []byte) ([]byte, error) {
	seq := atomic.AddUint64(&e.seqNum, 1) - 1

	// MAC: HMAC( MAC_write_key, seq_num(8) || type(1) || version(2) || length(2) || data )
	mac := hmac.New(e.macHash, e.macKey)
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, seq)
	mac.Write(b)
	mac.Write([]byte{recordType})
	mac.Write(tlsVersion)
	binary.Write(mac, binary.BigEndian, uint16(len(rawPayload)))
	mac.Write(rawPayload)
	macSum := mac.Sum(nil)
	macLen := len(macSum)

	// Padding: RFC 5246 section 6.2.3.2
	blockSize := e.block.BlockSize()
	paddingLen := blockSize - ((len(rawPayload)+macLen)%blockSize)
	if paddingLen == 0 {
		paddingLen = blockSize
	}
	padding := make([]byte, paddingLen)
	for i := range padding {
		padding[i] = byte(paddingLen - 1)
	}
	plaintext := append(rawPayload, macSum...)
	plaintext = append(plaintext, padding...)

	// Encrypt with CBC (IV is explicit in TLS 1.1+)
	ciphertext := make([]byte, len(plaintext))
	iv := e.iv
	mode := cipher.NewCBCEncrypter(e.block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	// TLS 1.1+ explicit IV: prepend to ciphertext
	explicitIV := iv
	length := len(explicitIV) + len(ciphertext)
	record := make([]byte, 0, 1+2+2+length)
	record = append(record, recordType)
	record = append(record, tlsVersion...)
	record = append(record, byte(length>>8), byte(length))
	record = append(record, explicitIV...)
	record = append(record, ciphertext...)
	return record, nil
}

// --- PRF and helpers ---

// RFC 5246: TLS PRF, only supporting SHA-256 or MD5/SHA1 for demo.
func prfSHA256(secret []byte, label string, seed []byte, needed int) ([]byte, error) {
	return prfGeneric(secret, label, seed, needed, sha256.New)
}
func prfSHA1(secret []byte, label string, seed []byte, needed int) ([]byte, error) {
	// MD5/SHA1 concatenation (for old suites) omitted; using SHA1 for demo.
	return prfGeneric(secret, label, seed, needed, sha1.New)
}
func prfGeneric(secret []byte, label string, seed []byte, needed int, hashFunc func() hash.Hash) ([]byte, error) {
	// TLS PRF(secret, label, seed) = P_hash(secret, label+seed)
	labelSeed := append([]byte(label), seed...)
	result := make([]byte, 0, needed)
	a := hmacHash(hashFunc, secret, labelSeed)
	for len(result) < needed {
		b := hmacHash(hashFunc, secret, append(a, labelSeed...))
		result = append(result, b...)
		a = hmacHash(hashFunc, secret, a)
	}
	return result[:needed], nil
}
func hmacHash(h func() hash.Hash, key, data []byte) []byte {
	m := hmac.New(h, key)
	m.Write(data)
	return m.Sum(nil)
}

// --- Optional: Mode string API ---

func (e *genericTLSRecordEncryptor) ModeString() string {
	return strings.ToUpper(e.mode.String())
}

// ---- Mock for reference ----
type MockTLSRecordEncryptor struct{}
func (m *MockTLSRecordEncryptor) SetTLSContext(ctx *TLSContext) error { return nil }
func (m *MockTLSRecordEncryptor) EncryptApplicationData(tlsVersion []byte, recordType byte, rawPayload []byte) ([]byte, error) {
	record := make([]byte, 0, 1+2+2+len(rawPayload))
	record = append(record, recordType)
	record = append(record, tlsVersion...)
	record = append(record, byte(len(rawPayload)>>8), byte(len(rawPayload)))
	record = append(record, rawPayload...)
	return record, nil
}
func (m *MockTLSRecordEncryptor) CipherMode() TLSCipherMode { return ModeUnknown }
