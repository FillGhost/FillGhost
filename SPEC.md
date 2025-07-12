

Internet-Draft                                          D. S. Developer
Intended status: Standards Track                               July 12, 2025
Expires: January 12, 2026

```
                   FillGhost Protocol: Covert Latency Padding
                   draft-developer-fillghost-protocol-00
```

Abstract

The FillGhost Protocol introduces a covert padding mechanism designed to obfuscate the intrinsic latency characteristics of proxy connections, specifically targeting the delay observed between a client's request being sent by a proxy and the proxy's first response from the target server. By injecting cryptographically random, valid-looking but semantically invalid TLS Application Data records into the client-facing stream during this critical latency window, FillGhost effectively masks the proxy's waiting period. These injected records appear as legitimate TLS application data to external observers, yet are silently discarded by the client's application layer, ensuring no detectable interaction or response. This protocol enhances censorship resistance by eliminating a potential timing-based fingerprint without altering core TLS functionality or requiring client-side protocol modifications.

Status of This Memo

This Internet-Draft is submitted in full conformance with the
provisions of BCP 78 and BCP 79.

Internet-Drafts are working documents of the Internet Engineering
Task Force (IETF). Note that other groups may also distribute
working documents as Internet-Drafts. The list of current Internet-
Drafts is at [https://datatracker.ietf.org/drafts/current/](https://datatracker.ietf.org/drafts/current/).

Internet-Drafts are draft documents valid for a maximum of six months
and may be updated, replaced, or obsoleted by other documents at any
time. It is inappropriate to use Internet-Drafts as reference
material or to cite them other than as "work in progress."

This Internet-Draft will expire on January 12, 2026.

Copyright Notice

Copyright (c) 2025 IETF Trust and the persons identified as the
document authors. All rights reserved.

This document is subject to BCP 78 and the IETF Trust's Legal
Provisions Relating to IETF Documents
([https://trustee.ietf.org/license-info](https://trustee.ietf.org/license-info)) in effect on the date of
publication of this document. Please review these documents
carefully, as they describe your rights and restrictions with
respect to this document. Code Components extracted from this
document must include Revised BSD License text as described in
Section 4.e of the Trust Legal Provisions and are provided without
warranty as described in the Revised BSD License.

Table of Contents

1.  Introduction
    1.1.  Motivation
    1.2.  Goals
2.  Terminology
3.  Protocol Overview
4.  FillGhost Packet Structure
5.  FillGhost Protocol Flow
    5.1.  Sender (Proxy Server) Operations
    5.2.  Receiver (Client) Operations
6.  Security Considerations
7.  IANA Considerations
8.  References
    8.1.  Normative References
    8.2.  Informative References
    Author's Address

## 1\. Introduction

### 1.1. Motivation

Modern censorship techniques increasingly rely on sophisticated traffic analysis, including timing-based side channels, to identify and block circumvention tools. While protocols like TLS provide strong confidentiality, the inherent latency introduced by proxying (the time taken for a proxy to forward a request and receive the initial response from a target server) can create a unique and identifiable timing fingerprint. This "proxy latency signature" can betray the presence of a proxy, even when other traffic characteristics are well-obfuscated. There is a need for a mechanism that specifically addresses this timing-based detection vector without compromising the integrity or confidentiality of the underlying TLS connection.

### 1.2. Goals

The FillGhost Protocol aims to achieve the following:

  * **Obfuscate Proxy Latency:** Mask the time delay between a proxy sending a client's request to a target server and receiving the first byte of that server's response.
  * **Maintain TLS Integrity:** Operate strictly within the established TLS tunnel, ensuring all injected data is encrypted and authenticated by the active TLS session keys.
  * **External Indistinguishability:** Ensure that all FillGhost-injected packets appear identical to legitimate TLS Application Data records to external observers.
  * **Silent Client Discard:** Guarantee that FillGhost packets are silently discarded by the client's application layer without generating any observable network response or error.
  * **Minimal Overhead:** Introduce minimal computational and bandwidth overhead, activating only during specific latency windows.
  * **Easy Integration:** Design as a lightweight plugin, requiring no modifications to standard TLS libraries for the client, and minimal modifications for the proxy.

## 2\. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 [RFC2119] [RFC8174] when they appear in all capitals, as
shown here.

**Client:** The user device running the proxy client software.
**Proxy Server:** The server-side component of the proxy that establishes a TLS connection with the Client and forwards traffic to target internet services.
**Target Server:** The legitimate internet service (e.g., a web server) that the Client wishes to access via the Proxy Server.
**FillGhost Packet:** A TLS Application Data record generated and sent by the Proxy Server to the Client, containing cryptographically random data, intended for silent discard by the client.
**Latency Window:** The time period between the Proxy Server sending a request to a Target Server and receiving the first response from that Target Server.

## 3\. Protocol Overview

The FillGhost Protocol operates exclusively on the **Proxy Server** side, within an established TLS tunnel with the Client. When the Proxy Server forwards a Client's request to a Target Server, it initiates a **Latency Window**. During this window, instead of remaining idle and exposing a timing fingerprint, the Proxy Server actively injects a stream of **FillGhost Packets** back to the Client.

These FillGhost Packets are constructed as valid TLS Application Data records, using the active TLS session keys for encryption and authentication. However, their internal payload consists solely of cryptographically random data, making them semantically invalid for the application layer. Upon reception, the Client's standard TLS stack will decrypt and authenticate these packets normally. The subsequent application layer protocol parser (e.g., HTTP/2, WebSocket) will then recognize the data as nonsensical or malformed and **silently discard** it, preventing any visible response or error. The injection of FillGhost Packets ceases immediately upon the Proxy Server receiving the first actual response from the Target Server, at which point the legitimate response data is forwarded to the Client.

This mechanism ensures that the client-facing side of the proxy connection consistently presents an active, legitimate-looking data flow, effectively masking the variable and potentially identifiable latency introduced by the proxying operation.

## 4\. FillGhost Packet Structure

A FillGhost Packet is a standard TLS Record Layer Application Data record, conforming to [RFC8446] (for TLS 1.3) or [RFC5246] (for TLS 1.2 and earlier).

Its external structure is indistinguishable from any other legitimate TLS Application Data record:

```
+-----------+-------+-------+
| Type (1B) | Ver(2B)| Len(2B)|  <-- TLS Record Header
+-----------+-------+-------+
|                               |
/       Encrypted Payload       / <-- Encrypted and Authenticated (AEAD)
|                               |     Application Data (FillGhost data)
+-------------------------------+
```

The key characteristics of a FillGhost Packet are:

  * **Record Type:** MUST be `0x17` (Application Data).
  * **TLS Version:** MUST match the negotiated TLS version of the current connection (e.g., `0x0304` for TLS 1.3, `0x0303` for TLS 1.2).
  * **Length:** The `Length` field in the TLS record header MUST reflect the actual encrypted length of the FillGhost payload. This length MUST be chosen randomly within a predefined range for each individual FillGhost packet, (e.g., **900 to 1400 bytes** for the *encrypted payload*).
  * **Encrypted Payload Content:** The entire content of the encrypted payload, after TLS decryption, MUST consist of **cryptographically secure random bytes**. This ensures that the decrypted data is semantically meaningless to any application layer protocol.

## 5\. FillGhost Protocol Flow

The FillGhost Protocol operates as a stateful module on the Proxy Server, triggered by outgoing client requests.

### 5.1. Sender (Proxy Server) Operations

For each client request received and forwarded to a Target Server:

1.  **Request Forwarding:** The Proxy Server **MUST** first forward the Client's request to the Target Server over its established connection.
2.  **Initial Delay (Optional but RECOMMENDED):** After forwarding the request, the Proxy Server **SHOULD** wait for a short, fixed duration (e.g., **3 milliseconds**). This initial delay helps simulate minimal network latency and provides a small buffer before FillGhost injection begins.
3.  **Initiate FillGhost Injection:** If no response from the Target Server is received after the initial delay, the Proxy Server **MUST** begin generating and sending FillGhost Packets to the Client.
      * **Packet Generation:** For each FillGhost Packet, the Proxy Server:
          * Generates a payload of cryptographically secure random bytes.
          * Determines a random length for this payload within the configured range (e.g., 900 to 1400 bytes).
          * Encapsulates this random payload into a standard TLS Application Data record.
          * Encrypts and authenticates the TLS record using the active TLS session keys established with the Client.
      * **Continuous Sending:** FillGhost Packets **SHOULD** be sent continuously, at the maximum sustainable rate, until the termination condition is met.
4.  **Termination Condition:** FillGhost Packet injection **MUST** cease immediately when the Proxy Server receives the **first byte or full initial response** from the Target Server.
5.  **Forward Legitimate Data:** Upon receiving data from the Target Server, the Proxy Server **MUST** immediately forward that legitimate data to the Client through the TLS tunnel, resuming normal proxy operations.

### 5.2. Receiver (Client) Operations

The Client requires no specific FillGhost-aware logic. It processes FillGhost Packets as follows:

1.  **TLS Record Reception:** The Client's standard TLS stack receives the FillGhost Packet.
2.  **TLS Decryption & Authentication:** The TLS stack **MUST** decrypt the record and verify its integrity (MAC/AEAD tag) using the established TLS session keys. Since FillGhost Packets are constructed as valid TLS records, this process will typically succeed.
3.  **Application Layer Delivery:** The decrypted payload is passed up to the Client's application layer protocol parser (e.g., HTTP/1.1, HTTP/2, WebSocket).
4.  **Silent Discard:** Because the decrypted payload consists of arbitrary random bytes, the application layer protocol parser **MUST NOT** recognize it as valid application data. Consequently, the parser **SHOULD silently discard** the data.
      * **No Response Generation:** The client **MUST NOT** generate any network-visible responses (e.g., application-layer error messages, TCP RSTs, or TLS Alert messages) as a result of discarding FillGhost data. This is critical for stealth.

## 6\. Security Considerations

  * **Randomness Quality:** All random bytes used for FillGhost Packet payloads MUST be generated using a cryptographically secure pseudo-random number generator (CSPRNG). Predictable random data could potentially be fingerprinted.
  * **TLS Session Security:** FillGhost relies entirely on the security of the underlying TLS connection. Any compromise of the TLS session keys would compromise the confidentiality of FillGhost packets, but their inherent random nature means no sensitive information is leaked.
  * **No Covert Channel:** FillGhost packets MUST NOT carry any meaningful hidden data. Their sole purpose is timing obfuscation. Any attempt to embed data could create a detectable covert channel.
  * **Bandwidth Overhead:** While FillGhost aims for minimal impact, it does introduce additional bandwidth consumption during latency windows. Implementations should consider configurable limits to prevent excessive usage in high-latency, high-volume scenarios.
  * **TCP Window Management:** Continuous injection of FillGhost packets could potentially fill the client's TCP receive window. Modern TCP stacks with large windows and window scaling should largely mitigate this, but it's a consideration for constrained environments. The immediate cessation of FillGhost injection upon real data arrival prevents prolonged window saturation.
  * **Traffic Analysis (Long-Term):** While FillGhost masks individual response latency, sophisticated, long-term traffic analysis correlating total bytes, connection durations, and initiation frequencies might still reveal proxy usage if not addressed by other obfuscation layers. FillGhost is a specialized tool for a specific timing fingerprint.

## 7\. IANA Considerations

This memo includes no IANA considerations.

## 8\. References

### 8.1. Normative References

[RFC2119]   Bradner, S., "Key words for use in RFCs to Indicate
Requirement Levels", BCP 14, RFC 2119,
DOI 10.17487/RFC2119, March 1997,
[https://www.rfc-editor.org/info/rfc2119](https://www.rfc-editor.org/info/rfc2119).

[RFC5246]   Dierks, T. and E. Rescorla, "The Transport Layer Security (TLS)
Protocol Version 1.2", RFC 5246, DOI 10.17487/RFC5246, August
2008, [https://www.rfc-editor.org/info/rfc5246](https://www.rfc-editor.org/info/rfc5246).

[RFC8174]   Leiba, B., "Ambiguity of Ought to and Should in RFCs",
BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017,
[https://www.rfc-editor.org/info/rfc8174](https://www.rfc-editor.org/info/rfc8174).

[RFC8446]   Rescorla, E., "The Transport Layer Security (TLS) Protocol
Version 1.3", RFC 8446, DOI 10.17487/RFC8446, August 2018,
[https://www.rfc-editor.org/info/rfc8446](https://www.rfc-editor.org/info/rfc8446).

### 8.2. Informative References

None.

Author's Address

D. S. Developer
Email: your.email@example.com (Replace with your actual email)
