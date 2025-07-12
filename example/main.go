package main

import (
	"context"
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

// MasterSecretExportMsg is now defined within the fillghost package
// This is to make the example runnable without modifying standard crypto/tls.
// In a real scenario, this type would originate from the modified crypto/tls library.
// For this example, we mock receiving such a message.
type MasterSecretExportMsg struct {
	SessionID    string // Identifier for the session, e.g., remote address
	TLSVersion   uint16 // Negotiated TLS version (e.g., tls.VersionTLS12, tls.VersionTLS13)
	CipherSuite  uint16 // Negotiated cipher suite ID
	MasterSecret []byte // Exported masterSecret
}

// ProxyServer simulates a proxy server demonstrating the integration of FillGhostManager.
type ProxyServer struct {
	listenAddr string
	targetAddr string
	tlsConfig  *tls.Config // TLS configuration for the server-side

	// This channel simulates receiving Master Secret from a *hypothetically* modified crypto/tls library.
	// In a real implementation, you would need to modify crypto/tls to send to this channel.
	masterSecretChan chan MasterSecretExportMsg
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
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS13,
	}

	// Create a buffered channel for master secret export messages.
	// WARNING: This channel is for conceptual demonstration ONLY.
	// Do NOT export master secrets in production.
	masterSecretChan := make(chan MasterSecretExportMsg, 100)

	return &ProxyServer{
		listenAddr:       listenAddr,
		targetAddr:       targetAddr,
		tlsConfig:        tlsConfig,
		masterSecretChan: masterSecretChan,
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

	// Goroutine to continuously receive and log exported master secrets.
	// In a real scenario with a modified crypto/tls, this would receive real keys.
	go func() {
		for msg := range ps.masterSecretChan {
			log.Printf("ProxyServer: Received Master Secret for session %s (TLS %x, Cipher %x): %x\n",
				msg.SessionID, msg.TLSVersion, msg.CipherSuite, msg.MasterSecret)
			// In a real FillGhost implementation, you would store this master secret
			// and other session parameters (like sequence numbers) per connection
			// and pass them to the real TLSRecordEncryptor.
			// For this example, we just log it.
		}
	}()

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

	connState := clientTLSConn.ConnectionState()
	negotiatedTLSVersion := make([]byte, 2)
	binary.BigEndian.PutUint16(negotiatedTLSVersion, connState.Version)

	log.Printf("ProxyServer: Negotiated TLS Version: 0x%x (TLS %d.%d)", connState.Version,
		(connState.Version>>8)&0xFF, connState.Version&0xFF)

	tlsEncryptor := fillghost.NewMockTLSRecordEncryptor(fmt.Sprintf("session-%s", clientTLSConn.RemoteAddr().String()))

	// !!! IMPORTANT !!!
	// For this *demonstration*, we are passing a DUMMY master secret and sequence numbers.
	// In a real FillGhost implementation, you *must* obtain the actual master secret
	// and current *outgoing* sequence numbers for this specific connection
	// from your **modified crypto/tls library**.
	// The `masterSecretChan` in `ProxyServer` would be the mechanism to receive the master secret.
	// You would need a mechanism to map it to the correct `clientTLSConn`.
	dummyMasterSecret := []byte("A_SUPER_SECRET_DUMMY_MASTER_SECRET_FOR_DEMO_PURPOSES") // Replace with actual exported key
	dummyClientSeqNum := uint64(0)                                                   // Replace with actual client-to-server sequence number
	dummyServerSeqNum := uint64(0)                                                   // Replace with actual server-to-client sequence number (this proxy's outgoing)

	err := tlsEncryptor.SetTLSContext(connState.Version, connState.CipherSuite,
		dummyMasterSecret, dummyClientSeqNum, dummyServerSeqNum)
	if err != nil {
		log.Printf("ProxyServer: Failed to set TLS context for encryptor: %v", err)
		return
	}

	sendToClientCallback := func(data []byte) error {
		log.Printf("ProxyServer: (Mock) Attempting to send FillGhost packet via clientTLSConn.Write().")
		_, err := clientTLSConn.Write(data)
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

	targetTLSConn, err := tls.Dial("tcp", ps.targetAddr, &tls.Config{InsecureSkipVerify: true}) // Use proper cert validation in prod
	if err != nil {
		log.Printf("ProxyServer: Failed to connect to target TLS server %s: %v", ps.targetAddr, err)
		return
	}
	defer targetTLSConn.Close()
	log.Printf("ProxyServer: Connected to target TLS server %s", ps.targetAddr)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer fillGhostManager.StopInjection()
		requestBuf := make([]byte, 4096)
		for {
			clientTLSConn.SetReadDeadline(time.Now().Add(10 * time.Second))
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

			_, err = targetTLSConn.Write(clientRequest)
			if err != nil {
				log.Printf("ProxyServer: Failed to write to target %s: %v", ps.targetAddr, err)
				return
			}
			log.Println("ProxyServer: Request forwarded to target server.")

			fillGhostManager.StartInjection()
		}
	}()

	go func() {
		defer wg.Done()
		responseBuf := make([]byte, 4096)
		for {
			targetTLSConn.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := targetTLSConn.Read(responseBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					log.Printf("ProxyServer: Target %s read timeout, closing connection.", ps.targetAddr)
				} else if err != io.EOF {
					log.Printf("ProxyServer: Target read error from %s: %v", ps.targetAddr, err)
				} else {
					log.Printf("ProxyServer: Target %s closed connection.", ps.targetAddr)
				}
				fillGhostManager.StopInjection()
				return
			}
			targetResponse := responseBuf[:n]
			log.Printf("ProxyServer: Received %d bytes from target (via TLS.Read): %s", len(targetResponse), string(targetResponse[:min(len(targetResponse), 50)]))

			fillGhostManager.StopInjection()

			_, err = clientTLSConn.Write(targetResponse)
			if err != nil {
				log.Printf("ProxyServer: Failed to send response to client %s: %v", clientTLSConn.RemoteAddr(), err)
				return
			}
			log.Printf("ProxyServer: Sent %d bytes of legitimate response to client %s.", len(targetResponse), clientTLSConn.RemoteAddr())
		}
	}()

	wg.Wait()
	log.Printf("ProxyServer: Connection with %s ended.", clientTLSConn.RemoteAddr())
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func generateSelfSignedCert(certFile, keyFile string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

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
		DNSNames:              []string{"localhost"},
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
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	certFile := "server.crt"
	keyFile := "server.key"
	if err := generateSelfSignedCert(certFile, keyFile); err != nil {
		log.Fatalf("Failed to generate self-signed certificate: %v", err)
	}
	log.Printf("Generated self-signed certificate and key at %s, %s", certFile, keyFile)

	proxy := NewProxyServer(":8888", "example.com:443", certFile, keyFile)
	proxy.Start()
}
