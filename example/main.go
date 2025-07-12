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

	"github.com/FillGhost/FillGhost"
)

// ProxyServer simulates a proxy server demonstrating the integration of FillGhostManager.
type ProxyServer struct {
	listenAddr string
	targetAddr string
	tlsConfig  *tls.Config // TLS configuration for the server-side
}

// NewProxyServer creates a new ProxyServer instance.
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
		go ps.handleClient(clientConn.(*tls.Conn))
	}
}

// handleClient handles a single client TLS connection.
func (ps *ProxyServer) handleClient(clientTLSConn *tls.Conn) {
	defer clientTLSConn.Close()
	log.Printf("ProxyServer: Accepted new client TLS connection from %s", clientTLSConn.RemoteAddr())

	if err := clientTLSConn.Handshake(); err != nil {
		log.Printf("ProxyServer: TLS handshake with %s failed: %v", clientTLSConn.RemoteAddr(), err)
		return
	}

	connState := clientTLSConn.ConnectionState()
	negotiatedTLSVersion := make([]byte, 2)
	binary.BigEndian.PutUint16(negotiatedTLSVersion, connState.Version)

	log.Printf("ProxyServer: Negotiated TLS Version: 0x%x (TLS %d.%d)", connState.Version,
		(connState.Version>>8)&0xFF, connState.Version&0xFF)

	// ----- 修改处：使用生产级别的加密器 -----
	encryptor := fillghost.NewTLSRecordEncryptor() // 生产级别接口

	// 注意: 真实 masterSecret、client/server random 这些目前无法直接从 tls.Conn 获得
	// 这里随便填充点假数据，防止报错，只保证接口调用不 panic
	ctx := &fillghost.TLSContext{
		TLSVersion:    negotiatedTLSVersion,
		CipherSuiteID: connState.CipherSuite,
		MasterSecret:  make([]byte, 48),         // 伪造长度不为0的 secret
		ClientRandom:  make([]byte, 32),         // 伪造
		ServerRandom:  make([]byte, 32),         // 伪造
		IsClient:      true,
	}
	err := encryptor.SetTLSContext(ctx)
	if err != nil {
		log.Printf("ProxyServer: [INFO] SetTLSContext failed: %v (this is normal if just for demo)", err)
	}

	// 这里可打印一下当前模式
	log.Printf("ProxyServer: FillGhost Encryptor using mode: %s", encryptor.CipherMode())

	// sendCallback，依然写入 tls.Conn
	sendToClientCallback := func(data []byte) error {
		log.Printf("ProxyServer: (Demo) send FillGhost packet (mock, will be re-encrypted).")
		_, err := clientTLSConn.Write(data)
		return err
	}

	fillGhostManager, err := fillghost.NewManager(
		encryptor,
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

	targetTLSConn, err := tls.Dial("tcp", ps.targetAddr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Printf("ProxyServer: Failed to connect to target TLS server %s: %v", ps.targetAddr, err)
		return
	}
	defer targetTLSConn.Close()
	log.Printf("ProxyServer: Connected to target TLS server %s", ps.targetAddr)

	var wg sync.WaitGroup
	wg.Add(2)

	// Client to Target
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

	// Target to Client
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

// generateSelfSignedCert generates a self-signed TLS certificate and key for testing.
// DO NOT USE IN PRODUCTION.
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
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
