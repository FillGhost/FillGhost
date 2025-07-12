package main

import (
	"net"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/FillGhost/FillGhost" // Corrected module import path
)

// ProxyServer simulates a proxy server demonstrating the integration of FillGhostManager.
type ProxyServer struct {
	listenAddr string
	targetAddr string
	tlsConfig  *tls.Config // TLS configuration for the server-side
}

// NewProxyServer creates a new ProxyServer instance.
// targetAddr: The address of the real destination server (e.g., "google.com:443").
// certFile: Path to the server's TLS certificate file.
// keyFile: Path to the server's TLS private key file.
func NewProxyServer(listenAddr, targetAddr, certFile, keyFile string) *ProxyServer {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("ProxyServer: Failed to load TLS certificate and key: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// In a real scenario, you might want to specify MinVersion and MaxVersion
		// For FillGhost, the important part is knowing the *negotiated* version for each connection.
		MinVersion: tls.VersionTLS10, // Support TLS 1.0 to 1.3 as per request
		MaxVersion: tls.VersionTLS13,
	}

	return &ProxyServer{
		listenAddr: listenAddr,
		targetAddr: targetAddr,
		tlsConfig:  tlsConfig,
	}
}

// Start initiates the proxy server.
func (ps *ProxyServer) Start() {
	listener, err := tls.Listen("tcp", ps.listenAddr, ps.tlsConfig)
	if err != nil {
		log.Fatalf("ProxyServer: Failed to listen TLS on %s: %v", ps.listenAddr, err)
	}
	defer listener.Close()
	log.Printf("ProxyServer: Listening TLS on %s, forwarding to %s", ps.listenAddr, ps.targetAddr)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("ProxyServer: Failed to accept client TLS connection: %v", err)
			continue
		}
		go ps.handleClient(clientConn.(*tls.Conn)) // Type assert to *tls.Conn
	}
}

// handleClient handles a single client TLS connection.
func (ps *ProxyServer) handleClient(clientTLSConn *tls.Conn) {
	defer clientTLSConn.Close()
	log.Printf("ProxyServer: Accepted new client TLS connection from %s", clientTLSConn.RemoteAddr())

	// Perform TLS handshake to get connection state
	if err := clientTLSConn.Handshake(); err != nil {
		log.Printf("ProxyServer: TLS handshake with %s failed: %v", clientTLSConn.RemoteAddr(), err)
		return
	}

	// Get negotiated TLS version from the active connection state.
	// This is crucial for the FillGhost's TLSRecordEncryptor.
	connState := clientTLSConn.ConnectionState()
	negotiatedTLSVersion := make([]byte, 2)
	binary.BigEndian.PutUint16(negotiatedTLSVersion, connState.Version)

	log.Printf("ProxyServer: Negotiated TLS Version: 0x%x (TLS %d.%d)", connState.Version,
		(connState.Version>>8)&0xFF, connState.Version&0xFF)

	// Instantiate the TLS record encryptor.
	// For this example, we still use the Mock. In production, this needs replacement.
	tlsEncryptor := fillghost.NewMockTLSRecordEncryptor(fmt.Sprintf("session-%s", clientTLSConn.RemoteAddr().String()))
	// Conceptually set TLS context for the encryptor.
	// In a real *tls.Conn integration*, this is where you'd pass necessary session secrets if possible.
	err := tlsEncryptor.SetTLSContext(negotiatedTLSVersion, connState.CipherSuite, []byte("conceptually_derived_master_secret"))
	if err != nil {
		log.Printf("ProxyServer: Failed to set TLS context for encryptor: %v", err)
		return
	}

	// The sendCallback function for FillGhost Manager.
	// This function *must* write directly to the underlying net.Conn *before* tls.Conn
	// for pre-formed TLS records (like FillGhost) to bypass the tls.Conn's own encryption.
	// This is a complex point in Go's crypto/tls design.
	// For this example, we directly write to the *tls.Conn*, which means the mock
	// FillGhost packets will be *re-encrypted* by tls.Conn, which is NOT the intended
	// behavior of FillGhost for stealth. This highlights the limitation.
	sendToClientCallback := func(data []byte) error {
		// In a true FillGhost implementation, `data` (which is already a mock TLS record)
		// would need to be written *directly* to the underlying `net.Conn` of `clientTLSConn`
		// *without* going through `clientTLSConn.Write()`.
		// Accessing the underlying `net.Conn` of a `*tls.Conn` is not directly exposed
		// in a public API. It often requires type assertions and understanding of
		// internal structures or wrapping the net.Conn before tls.Client/Server.
		log.Printf("ProxyServer: (Mock) Attempting to send FillGhost packet via clientTLSConn.Write().")
		_, err := clientTLSConn.Write(data) // This will cause `data` to be re-encrypted by *tls.Conn
		return err
	}

	fillGhostManager, err := fillghost.NewManager(
		tlsEncryptor,
		sendToClientCallback,
		3,    // Initial delay in ms
		900,  // Min FillGhost packet payload length
		1400, // Max FillGhost packet payload length
		negotiatedTLSVersion,
	)
	if err != nil {
		log.Printf("ProxyServer: Failed to create FillGhostManager: %v", err)
		return
	}

	// --- Connect to Target Server (real TLS connection) ---
	targetTLSConn, err := tls.Dial("tcp", ps.targetAddr, &tls.Config{InsecureSkipVerify: true}) // Use proper cert validation in prod
	if err != nil {
		log.Printf("ProxyServer: Failed to connect to target TLS server %s: %v", ps.targetAddr, err)
		return
	}
	defer targetTLSConn.Close()
	log.Printf("ProxyServer: Connected to target TLS server %s", ps.targetAddr)

	// --- Goroutines for bidrectional data transfer ---
	var wg sync.WaitGroup
	wg.Add(2)

	// Client to Target
	go func() {
		defer wg.Done()
		defer fillGhostManager.StopInjection() // Ensure injection stops if client side closes
		// We use a custom io.Copy here to detect when a request is sent.
		// A real proxy would parse application layer data (e.g., HTTP/S frames)
		// to determine when a logical request has been fully forwarded.
		requestBuf := make([]byte, 4096)
		for {
			clientTLSConn.SetReadDeadline(time.Now().Add(10 * time.Second)) // Set a read timeout for client
			n, err := clientTLSConn.Read(requestBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					log.Printf("ProxyServer: Client %s read timeout, closing connection.", clientTLSConn.RemoteAddr())
				} else if err != io.EOF {
					log.Printf("ProxyServer: Client read error from %s: %v", clientTLSConn.RemoteAddr(), err)
				} else {
					log.Printf("ProxyServer: Client %s closed connection.", clientTLSConn.RemoteAddr())
				}
				return
			}
			clientRequest := requestBuf[:n]
			log.Printf("ProxyServer: Received %d bytes from client (via TLS.Read): %s", len(clientRequest), string(clientRequest[:min(len(clientRequest), 50)]))

			// Write client request to target
			_, err = targetTLSConn.Write(clientRequest)
			if err != nil {
				log.Printf("ProxyServer: Failed to write to target %s: %v", ps.targetAddr, err)
				return
			}
			log.Println("ProxyServer: Request forwarded to target server.")

			// Start FillGhost injection immediately after forwarding the request
			fillGhostManager.StartInjection()
		}
	}()

	// Target to Client
	go func() {
		defer wg.Done()
		responseBuf := make([]byte, 4096)
		for {
			targetTLSConn.SetReadDeadline(time.Now().Add(10 * time.Second)) // Set a read timeout for target
			n, err := targetTLSConn.Read(responseBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					log.Printf("ProxyServer: Target %s read timeout, closing connection.", ps.targetAddr)
				} else if err != io.EOF {
					log.Printf("ProxyServer: Target read error from %s: %v", ps.targetAddr, err)
				} else {
					log.Printf("ProxyServer: Target %s closed connection.", ps.targetAddr)
				}
				// When target closes connection or an error occurs, stop FillGhost injection.
				fillGhostManager.StopInjection()
				return
			}
			targetResponse := responseBuf[:n]
			log.Printf("ProxyServer: Received %d bytes from target (via TLS.Read): %s", len(targetResponse), string(targetResponse[:min(len(targetResponse), 50)]))

			// Stop FillGhost injection as soon as the first byte/response from the target arrives
			fillGhostManager.StopInjection()

			// Forward the legitimate response to the client
			_, err = clientTLSConn.Write(targetResponse)
			if err != nil {
				log.Printf("ProxyServer: Failed to send response to client %s: %v", clientTLSConn.RemoteAddr(), err)
				return
			}
			log.Printf("ProxyServer: Sent %d bytes of legitimate response to client %s.", len(targetResponse), clientTLSConn.RemoteAddr())
		}
	}()

	wg.Wait() // Wait for both directions to complete
	log.Printf("ProxyServer: Connection with %s ended.", clientTLSConn.RemoteAddr())
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// generateSelfSignedCert generates a self-signed TLS certificate and key for testing.
// DO NOT USE IN PRODUCTION.
func generateSelfSignedCert(certFile, keyFile string) error {
	// Minimal self-signed cert generation for testing purposes
	// This is simplified and does not handle all real-world certificate complexities.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"FillGhost Proxy Test"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"}, // For testing on localhost
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to open cert.pem for writing: %w", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("failed to open key.pem for writing: %w", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return nil
}

func main() {
	// Configure logging to include timestamps with microseconds for better timing observation
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// --- Generate self-signed TLS certificate for the proxy server (for testing) ---
	// In production, use a proper CA-signed certificate.
	certFile := "server.crt"
	keyFile := "server.key"
	if err := generateSelfSignedCert(certFile, keyFile); err != nil {
		log.Fatalf("Failed to generate self-signed certificate: %v", err)
	}
	log.Printf("Generated self-signed certificate and key at %s, %s", certFile, keyFile)

	// Proxy listens on :8888, forwards to example.com:443
	proxy := NewProxyServer(":8888", "example.com:443", certFile, keyFile)
	proxy.Start()
}
