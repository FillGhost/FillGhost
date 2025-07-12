# FillGhost Proxy Example

This repository presents a conceptual example of a proxy server demonstrating the integration of the **FillGhost Protocol**. FillGhost aims to obscure communication patterns by injecting legitimate-looking but meaningless TLS application data records during periods of network idleness, specifically when a proxy is waiting for a response from a target server.

## Project Structure

```
├── github.com/FillGhost/FillGhost/
│   ├── generator.go      # Random data and length generation
│   ├── encryptor.go      # Conceptual TLS record encryption interface and mock
│   └── manager.go        # Core FillGhost injection logic
└── README.md                 # This README file
```

## What is FillGhost?

FillGhost is a conceptual protocol designed to enhance traffic obfuscation by preventing timing-based attacks (e.g., traffic analysis) that exploit the periods of silence in a connection. When a proxy forwards a client's request to a remote server and waits for a response, there's a natural "silent" gap. FillGhost fills this gap by injecting specially crafted TLS Application Data records.

Key characteristics of FillGhost packets:

  * **Legitimate TLS Records:** These are fully valid TLS Application Data records, correctly encrypted and authenticated with the active session keys. This is crucial for **stealth**.
  * **Application-Layer Meaningless:** The payload inside these records is random data. A well-behaved application-layer parser (e.g., for HTTP/2) is expected to **silently discard** this meaningless data without generating any network-visible responses or TLS Alert messages.
  * **Preventing Alerts:** Unlike simply sending random, unencrypted, or incorrectly encrypted bytes, FillGhost packets *do not* trigger TLS alerts (like `bad_record_mac` or `decrypt_error`) because they are cryptographically correct at the TLS record layer.

## How This Example Works (and its Limitations)

This example demonstrates the FillGhost logic in a Go proxy, but it comes with a **significant conceptual limitation** concerning Go's standard `crypto/tls` library.

### The Challenge with `crypto/tls` and Internal Keys

Go's `crypto/tls` library is designed for security and ease of use. It **does not expose internal TLS session keys (like `master_secret` or derived traffic keys) or granular control over record construction and sequence numbers through its public API.** This is a security feature to prevent accidental or malicious compromise of TLS sessions.

However, for FillGhost to work correctly, the proxy needs to:

1.  **Access the active TLS symmetric session keys** (specifically, the server-to-client direction keys).
2.  **Generate and encrypt arbitrary data** using these keys, mimicking how `crypto/tls` itself encrypts application data.
3.  **Inject these fully formed and encrypted TLS records** directly onto the underlying TCP connection, *bypassing* the `tls.Conn`'s own `Write` method (which would re-encrypt or reject foreign records).

**Due to the limitations of the public `crypto/tls` API, a fully functional, cryptographically correct FillGhost implementation in Go, without modifying the standard library, is extremely challenging.**

### How This Example Addresses the Limitation (Conceptually)

This example's `MockTLSRecordEncryptor` component in `github.com/FillGhost/FillGhost/encryptor.go` is a **conceptual placeholder**. It attempts to simulate real TLS record encryption (using `crypto/aes` and `crypto/cipher` for AEAD operations) *as if* it had access to the actual symmetric keys and sequence numbers.

**To make a *real* FillGhost implementation in Go, you would likely need to:**

1.  **Modify Go's `crypto/tls` Standard Library Source Code:**

      * You would need to insert code directly into files like `src/crypto/tls/conn.go` to **export the `master_secret`** (or relevant traffic keys for TLS 1.3) and the current **outgoing sequence numbers** for each TLS connection. This exported data would then be sent via a channel or a callback to your FillGhost manager.
      * You would also need a mechanism within the modified `crypto/tls` to **allow injecting pre-formed TLS records** onto the underlying `net.Conn` without them being processed or re-encrypted by `tls.Conn` itself. This is highly complex.
      * **WARNING:** Modifying and recompiling the Go standard library is **highly insecure** for production environments and makes your Go installation non-standard and hard to maintain. **This example does NOT include these actual `crypto/tls` modifications; it only conceptualizes their necessity.**

2.  **Use a Different TLS Library or Custom TLS Stack:**

      * Alternatively, you might use a different TLS library (e.g., through Cgo bindings to OpenSSL) that provides more granular control over session keys and record manipulation. Or, you could implement a custom TLS stack (an extremely complex undertaking).

**In this example, the `main.go` file passes a `DUMMY_MASTER_SECRET_FOR_CONCEPTUAL_DEMO` to `MockTLSRecordEncryptor.SetTLSContext`. This allows the example to *run* and *demonstrate the FillGhost logic*, but the encrypted packets it sends are not truly encrypted with the actual live TLS session keys. Therefore, if sent to a real client (without the `crypto/tls` modification to correctly get and use the keys), they might trigger TLS alerts or be rejected by the client's TLS stack.**

## How to Run the Example

This example sets up a simple TLS proxy.

### Prerequisites

  * Go 1.18+ installed.

### Steps

1.  **Clone the repository (or create the file structure manually):**

    ```bash
    mkdir -p fillghost_project/cmd/fillghost_proxy
    mkdir -p fillghost_project/github.com/FillGhost/FillGhost
    cd fillghost_project
    ```

2.  **Create the Go module:**

    ```bash
    go mod init fillghost_project
    ```

    Then, create `github.com/FillGhost/FillGhost` as a pseudo-module inside `fillghost_project/go.mod`:

    ```go
    module fillghost_project

    go 1.18

    // This makes the FillGhost package a local replacement for demonstration
    replace github.com/FillGhost/FillGhost => ./github.com/FillGhost/FillGhost
    ```

3.  **Place the Go source files:**

      * Place `generator.go` into `github.com/FillGhost/FillGhost/generator.go`
      * Place `encryptor.go` into `github.com/FillGhost/FillGhost/encryptor.go`
      * Place `manager.go` into `github.com/FillGhost/FillGhost/manager.go`
      * Place `main.go` into `cmd/fillghost_proxy/main.go`

4.  **Run the proxy server:**
    From the `fillghost_project` root directory:

    ```bash
    go run cmd/fillghost_proxy/main.go
    ```

    You should see output indicating the proxy is listening and generating a self-signed certificate.

### Testing the Proxy (Conceptual)

The proxy listens on `https://localhost:8888` and forwards to `https://example.com:443`.

You can test it using `curl` (you'll need to bypass certificate validation due to the self-signed cert):

```bash
curl -k https://localhost:8888
```

**Expected Output:**

  * In your proxy's terminal, you'll see logs about accepting connections, forwarding requests, and crucially, `ProxyServer: (Mock) Attempting to send FillGhost packet via clientTLSConn.Write().`
  * `curl` will receive the content from `example.com`.

**What you are *not* seeing (and why):**

  * You won't see actual FillGhost packets being injected *on the network level* that are correctly encrypted with the live session keys. This is because, as explained, the `crypto/tls` library would need modification to provide those keys and allow direct injection without re-encryption.
  * The `MockTLSRecordEncryptor` in this example generates data that *looks like* a valid TLS record header + AEAD encrypted payload, but it uses a **dummy master secret and sequence numbers**. When `clientTLSConn.Write(data)` is called, the `tls.Conn` instance will actually take these "mock TLS records" and **re-encrypt them** (or potentially treat them as raw application data to be re-framed and re-encrypted). This is not the intended FillGhost behavior.

## Conclusion

This project serves as a clear illustration of the FillGhost protocol's design and how its components (generator, encryptor, manager) would interact within a proxy. It highlights the significant challenges of implementing such a protocol in Go due to the secure, black-box nature of its `crypto/tls` library.

For a truly effective and stealthy FillGhost implementation in Go, deep modifications to the `crypto/tls` standard library source code or the use of a more low-level TLS implementation (potentially via Cgo) would be necessary to gain access to session keys and perform direct, un-interfered-with record injection.

---

## Recommended TLS Libraries for FillGhost Users

Implementing FillGhost effectively requires low-level access to TLS session keys and control over record construction and injection, capabilities that Go's standard `crypto/tls` library intentionally restricts for security and simplicity. If you're serious about building a robust FillGhost solution, you'll likely need to consider alternatives that offer more granular control.

Here are the recommended TLS libraries that provide the necessary flexibility for FillGhost, listed with their pros and cons:

### 1. OpenSSL (C/C++)

**OpenSSL** is the industry standard for low-level TLS/SSL programming. If maximum control, performance, and deep protocol manipulation are your priorities, this is your go-to.

* **Pros:**
    * **Unparalleled Control:** Provides APIs to manage every aspect of a TLS session, including session key extraction, manual record layer construction, and direct network injection.
    * **High Performance:** Optimized for speed and efficiency, crucial for network proxies.
    * **Widely Adopted:** Extensive documentation, community support, and a proven track record in critical applications.
* **Cons:**
    * **Extreme Complexity:** The API is notoriously intricate, with a very steep learning curve.
    * **Memory Management:** Requires manual memory handling, increasing the risk of memory leaks or vulnerabilities if not managed meticulously.
    * **Development Time:** Expect significantly longer development and debugging cycles compared to higher-level libraries.

### 2. Go-OpenSSL (Go with Cgo)

This option allows you to leverage the power of **OpenSSL within your Go projects** by using **Cgo bindings** (e.g., `github.com/mreiferson/go-openssl`). It's a hybrid approach that can give you the best of both worlds.

* **Pros:**
    * **OpenSSL's Capabilities:** Access to OpenSSL's comprehensive set of features, including key management and record manipulation.
    * **Go's Concurrency:** You can still utilize Go's excellent concurrency model (goroutines) for your proxy logic.
    * **Familiarity (for Go devs):** You're still primarily writing Go code, even with the Cgo calls.
* **Cons:**
    * **Cgo Overhead:** Introduces Cgo complexities, which can make compilation harder, debugging more challenging, and might slightly impact performance compared to pure Go.
    * **External Dependency:** Requires OpenSSL to be installed on the system where your application runs.
    * **Increased Attack Surface:** Binding to a C library can expose your Go application to potential vulnerabilities in the C code or its dependencies.

### 3. Rustls (Rust)

**Rustls** is a modern, memory-safe TLS library written entirely in **Rust**. While it prioritizes correctness and safety, its design often allows for more direct interaction with TLS internals than Go's `crypto/tls` for specific, advanced use cases.

* **Pros:**
    * **Memory Safety:** Written in Rust, it inherently prevents common memory errors that plague C/C++ libraries.
    * **Modern Design:** Clean, well-architected codebase that's easier to reason about than legacy C libraries.
    * **Good Performance:** Rust's performance is comparable to C/C++.
* **Cons:**
    * **Newer Ecosystem:** Less mature and fewer third-party integrations compared to OpenSSL.
    * **Learning Curve:** Requires learning Rust, which has a steeper learning curve than Go or Python.
    * **Control Level:** While more flexible than Go's standard library, it might not offer the *absolute lowest level* of byte-level control that OpenSSL does without deeper internal modifications.

---
