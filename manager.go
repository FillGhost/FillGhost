package fillghost

import (
	"context"
	"log"
	"sync"
	"time"
)

// FillGhostManager is the core manager for the FillGhost Protocol.
// It is responsible for injecting padding packets to the client while the proxy server
// is awaiting a response from the target server.
type FillGhostManager struct {
	tlsEncryptor    TLSRecordEncryptor // Interface to encrypt data into TLS records
	packetGenerator *PacketGenerator   // Generates random data and lengths
	sendCallback    func([]byte) error // Callback to send encrypted data to the client

	initialDelay    time.Duration      // Initial delay before injection starts (e.g., 3ms)
	minFillGhostLen int                // Minimum random length for FillGhost packet payload
	maxFillGhostLen int                // Maximum random length for FillGhost packet payload
	tlsVersion      []byte             // The 2-byte TLS version currently negotiated with the client (e.g., [0x03, 0x04])

	injectionCtx    context.Context    // Context for controlling the injection goroutine
	cancelInjection context.CancelFunc // Function to cancel the injection context
	injectionWg     sync.WaitGroup     // WaitGroup to wait for the injection goroutine to finish
	isInjecting     bool               // Current injection status flag
	mu              sync.Mutex         // Mutex to protect injection status
}

// NewManager creates a new FillGhostManager instance.
//
// tlsEncryptor: An implementation of TLSRecordEncryptor to handle TLS record encryption.
// sendCallback: A callback function used to send the encrypted FillGhost packet to the client.
//               The function signature should be `func(data []byte) error`.
// initialDelayMs: The initial delay in milliseconds after the proxy forwards a request
//                 before FillGhost packet injection begins.
// minFillGhostLen: The minimum random length in bytes for the raw payload of each FillGhost packet.
// maxFillGhostLen: The maximum random length in bytes for the raw payload of each FillGhost packet.
// tlsVersion: The 2-byte TLS version currently negotiated with the client (e.g., [0x03, 0x04] for TLS 1.3).
func NewManager(
	tlsEncryptor TLSRecordEncryptor,
	sendCallback func([]byte) error,
	initialDelayMs int,
	minFillGhostLen int,
	maxFillGhostLen int,
	tlsVersion []byte,
) (*FillGhostManager, error) {
	if tlsEncryptor == nil {
		return nil, fmt.Errorf("fillghost: NewManager: TLSRecordEncryptor cannot be nil")
	}
	if sendCallback == nil {
		return nil, fmt.Errorf("fillghost: NewManager: sendCallback cannot be nil")
	}
	if initialDelayMs < 0 {
		return nil, fmt.Errorf("fillghost: NewManager: initialDelayMs must be non-negative")
	}
	if minFillGhostLen < 0 || maxFillGhostLen < 0 || minFillGhostLen > maxFillGhostLen {
		return nil, fmt.Errorf("fillghost: NewManager: minFillGhostLen and maxFillGhostLen must be non-negative, and minFillGhostLen <= maxFillGhostLen")
	}
	if len(tlsVersion) != 2 {
		return nil, fmt.Errorf("fillghost: NewManager: tlsVersion must be a 2-byte slice representing the TLS version")
	}

	log.Printf("fillghost: Manager initialized. Initial delay: %dms, padding length range: %d-%d bytes.",
		initialDelayMs, minFillGhostLen, maxFillGhostLen)

	return &FillGhostManager{
		tlsEncryptor:    tlsEncryptor,
		sendCallback:    sendCallback,
		initialDelay:    time.Duration(initialDelayMs) * time.Millisecond,
		minFillGhostLen: minFillGhostLen,
		maxFillGhostLen: maxFillGhostLen,
		packetGenerator: NewPacketGenerator(), // Initialize a new packet generator
		tlsVersion:      tlsVersion,
	}, nil
}

// StartInjection initiates FillGhost packet injection.
// This method should be called immediately after the proxy server forwards a client request
// to the target server.
func (fgm *FillGhostManager) StartInjection() {
	fgm.mu.Lock()
	defer fgm.mu.Unlock()

	if fgm.isInjecting {
		log.Println("fillghost: WARNING: Injection is already in progress.")
		return
	}

	fgm.injectionCtx, fgm.cancelInjection = context.WithCancel(context.Background())
	fgm.injectionWg.Add(1) // Increment the WaitGroup counter
	go fgm.injectionLoop() // Start the injection in a new goroutine
	fgm.isInjecting = true
	log.Println("fillghost: Injection started.")
}

// StopInjection halts FillGhost packet injection.
// This method should be called immediately upon the proxy server receiving the first response
// from the target server.
func (fgm *FillGhostManager) StopInjection() {
	fgm.mu.Lock()
	defer fgm.mu.Unlock()

	if !fgm.isInjecting {
		log.Println("fillghost: WARNING: Injection is not currently active.")
		return
	}

	fgm.cancelInjection() // Signal the injection goroutine to stop
	fgm.injectionWg.Wait() // Wait for the injection goroutine to complete
	fgm.isInjecting = false
	log.Println("fillghost: Injection stopped.")
}

// injectionLoop is the core loop for FillGhost packet injection, running in a separate goroutine.
func (fgm *FillGhostManager) injectionLoop() {
	defer fgm.injectionWg.Done() // Decrement WaitGroup counter when goroutine exits

	log.Printf("fillghost: Injection goroutine started. Waiting for initial delay %s...", fgm.initialDelay)
	select {
	case <-time.After(fgm.initialDelay):
		// Initial delay has passed
		log.Println("fillghost: Starting to send FillGhost packets...")
		for {
			select {
			case <-fgm.injectionCtx.Done(): // Check for cancellation signal
				log.Println("fillghost: Injection goroutine received stop signal, exiting.")
				return
			default:
				// Continue sending FillGhost packets
				payloadLen, err := fgm.packetGenerator.GetRandomFillGhostLength(fgm.minFillGhostLen, fgm.maxFillGhostLen)
				if err != nil {
					log.Printf("fillghost: ERROR: Failed to generate FillGhost payload length: %v. Stopping injection.", err)
					return // Critical error, stop injection
				}
				randomPayload, err := fgm.packetGenerator.GenerateRandomBytes(payloadLen)
				if err != nil {
					log.Printf("fillghost: ERROR: Failed to generate FillGhost payload bytes: %v. Stopping injection.", err)
					return // Critical error, stop injection
				}

				// Encrypt the random payload into a TLS Application Data record.
				// RecordType for Application Data is 0x17.
				fillGhostPacket, err := fgm.tlsEncryptor.EncryptApplicationData(fgm.tlsVersion, 0x17, randomPayload)
				if err != nil {
					log.Printf("fillghost: ERROR: Failed to encrypt FillGhost packet: %v. Stopping injection.", err)
					return // Encryption failure typically indicates a TLS session issue, so stop
				}

				// Send the encrypted packet to the client via the callback.
				err = fgm.sendCallback(fillGhostPacket)
				if err != nil {
					log.Printf("fillghost: ERROR: Failed to send FillGhost packet: %v. Stopping injection.", err)
					// Sending failure usually means the connection is broken, so stop
					return
				}
				// log.Printf("fillghost: Sent a %d-byte FillGhost packet.\n", len(fillGhostPacket)) // Uncomment for verbose logging

				// In a real scenario, the sendCallback's Write operation will naturally block
				// if the send buffer is full, providing a natural rate limit.
				// If sendCallback is non-blocking, a small sleep (e.g., time.Microsecond) might be needed
				// here to prevent 100% CPU usage if packets are generated faster than they can be sent.
			}
		}
	case <-fgm.injectionCtx.Done(): // Context cancelled during initial delay
		log.Println("fillghost: Injection goroutine cancelled during initial delay, exiting.")
		return
	}
}
