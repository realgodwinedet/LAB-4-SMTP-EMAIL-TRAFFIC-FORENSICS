
# SBT-DF203 — BASIC NETWORKING SKILLS FOR DIGITAL FORENSICS

## LAB 4 — SMTP EMAIL TRAFFIC FORENSICS

| Student Information | Entry |
| --- | --- |
| **Full Name** | Godwin Edet Ikpi |
| **Registration Number** | 2025/FWSD/11267 |
| **Programme / Class** | DIGITAL FORENSICS |
| **Date Performed** | 9th September 2026 |
| **PCAP Filename** | `smtp.pcap` |
| **Report Filename** | `SBT-DF203-Lab4` |

---

### 1. Executive Summary

This practical examines an authorised historical SMTP packet capture (`smtp.pcap`) to identify when email exchange occurred, identify client/server systems, reconstruct SMTP commands and message content, decode relevant Base64 values offline, and assess whether STARTTLS/TLS protected subsequent traffic. The original `smtp.pcap` is preserved unchanged in an `original/` directory, and all evidence-dependent values in this report are populated directly from terminal execution and Wireshark/TShark analyses.

---

### 2. Scenario and Objectives

* **Scenario:** Analyse a historical SMTP packet capture to determine when email exchange occurred, identify client/server systems, reconstruct SMTP commands/message content, decode relevant Base64 fields offline, and document network/encryption evidence safely.
* **Objectives:**
* Explain SMTP and common ports.
* Identify SMTP commands and response codes.
* Reconstruct the relevant SMTP TCP stream.
* Decode required Base64 training values offline while redacting sensitive values in the report.
* Extract message headers, client software indicators, IP addresses, TCP ports, and MAC addresses.
* Assess STARTTLS/TLS and state the evidential limitations caused by encryption.



---

### 3. Authorisation, Safety and Evidence Handling

Only the authorised SMTP training PCAP supplied for SBT-DF203 was used. No live, third-party, public, production, or wireless traffic was intercepted. No real credentials or sensitive emails were transmitted. The original capture file was preserved, and analysis was executed entirely on a verified working copy.

| Requirement | Recorded action |
| --- | --- |
| **Original evidence** | `smtp.pcap` preserved unchanged |
| **Working copy** | `~/SBT-DF203-Lab4/working/smtp.pcap` |
| **Authorised source** | SBT-DF203 SMTP training resource |
| **Analysis environment** | Kali Linux 2024.1 / Wireshark 4.2.0 / TShark 4.2.0 |
| **Sensitive data handling** | Credentials and unnecessary personal content redacted |

---

### 4. Evidence Preservation and Hashing

```bash
mkdir -p ~/SBT-DF203-Lab4/{original,working,output,logs,screenshots}
cp smtp.pcap ~/SBT-DF203-Lab4/original/smtp.pcap
cp ~/SBT-DF203-Lab4/original/smtp.pcap ~/SBT-DF203-Lab4/working/smtp.pcap
sha256sum ~/SBT-DF203-Lab4/original/smtp.pcap
sha256sum ~/SBT-DF203-Lab4/working/smtp.pcap
cmp ~/SBT-DF203-Lab4/original/smtp.pcap ~/SBT-DF203-Lab4/working/smtp.pcap
capinfos ~/SBT-DF203-Lab4/working/smtp.pcap

```

| Evidence item | Value |
| --- | --- |
| **Original SHA-256** | `17ad230db1b6fd5dd18eb311092df1cf6eb162054bdb47697b89bef5a86a47ab` |
| **Working-copy SHA-256** | `17ad230db1b6fd5dd18eb311092df1cf6eb162054bdb47697b89bef5a86a47ab` |
| **Hash match** | **MATCH** |
| **File size** | 27 kB (26,866 bytes data size) |
| **Packet count** | 60 |
| **Capture start** | 2009-10-05 02:06:07.492060 EDT |
| **Capture end** | 2009-10-05 02:06:16.690444 EDT |
| **Capture duration** | 9.198384 seconds |
| **Link-layer type** | Ethernet |

> **Evidence Checkpoint 1:** Screenshot showing the original/working-copy hashes and `capinfos` output.

---

### 5. SMTP Overview and Common Ports

| Port | Typical use | Security note |
| --- | --- | --- |
| **25** | SMTP server-to-server / relay | May be plaintext unless STARTTLS is negotiated. |
| **587** | Message submission | Common submission port; often uses STARTTLS. |
| **465** | SMTP over implicit TLS | TLS is established before SMTP commands are exposed. |

---

### 6. Lab Environment

| Component | Recorded value |
| --- | --- |
| **Operating system** | Kali Linux 2024.1 |
| **Wireshark version** | Wireshark 4.2.0 |
| **TShark version** | TShark 4.2.0 |
| **PCAP** | `smtp.pcap` |
| **Analysis mode** | Offline / historical PCAP |
| **Analyst** | IKPI GODWIN EDET |

---

### 7. SMTP Conversation Inventory

```bash
tshark -r ~/SBT-DF203-Lab4/working/smtp.pcap -q -z conv,tcp
tshark -r ~/SBT-DF203-Lab4/working/smtp.pcap -Y smtp -T fields \
  -e frame.number -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
  -e tcp.stream -e smtp.request.command -e smtp.response.code

```

| TCP stream | Client endpoint | Server endpoint | Ports | Packets | Observation |
| --- | --- | --- | --- | --- | --- |
| **0** | `10.10.1.4:1470` | `74.53.140.153:25` | 1470 → 25 | 53 | Single active TCP stream carrying SMTP traffic |

> **Evidence Checkpoint 2:** Screenshot showing the SMTP conversation inventory.

---

### 8. Endpoint Identification

```bash
tshark -r ~/SBT-DF203-Lab4/working/smtp.pcap -Y smtp -T fields \
  -e frame.number -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.stream

```

| Role | IP address | TCP port | MAC address | Evidence packet(s) |
| --- | --- | --- | --- | --- |
| **SMTP client** | `10.10.1.4` | 1470 | `00:e0:1c:3c:17:c2` | Frame 3, 5, 7 / Stream 0 |
| **SMTP server** | `74.53.140.153` | 25 | `00:1f:33:d9:81:60` | Frame 4, 6 / Stream 0 |

> **Evidence Checkpoint 3:** Screenshot showing endpoint IPs, ports, and MAC addresses.

---

### 9. 220 Service-Ready Response

```bash
tshark -r ~/SBT-DF203-Lab4/working/smtp.pcap -Y 'smtp.response.code == 220' -T fields \
  -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.stream -e smtp.response.code -e smtp.response.parameter

```

| Frame | Time | Server IP | Client IP | TCP stream | Code | Greeting text |
| --- | --- | --- | --- | --- | --- | --- |
| **6** | 05 Oct 2009 02:06:08 EDT | `74.53.140.153` | `10.10.1.4` | 0 | 220 | `220-xc90.websitewelcome.com ESMTP Exim 4.69` |

> **Evidence Checkpoint 4:** Wireshark screenshot clearly showing the 220 service-ready response.

---

### 10. EHLO / HELO Exchange

```bash
tshark -r ~/SBT-DF203-Lab4/working/smtp.pcap -Y 'smtp.request.command == "EHLO" || smtp.request.command == "HELO"' \
  -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.stream -e smtp.request.command -e smtp.request.parameter

```

| Frame | Time | Command | Client/server | Parameter | Server response |
| --- | --- | --- | --- | --- | --- |
| **7** | Oct 5, 2009 02:06:08.224809 EDT | `EHLO` | Client → Server | `GP` | `250-xc90.websitewelcome.com Hello GP [122.162.143.157]` |

#### Advertised Capabilities Table

| Capability | Observed? | Evidence |
| --- | --- | --- |
| **AUTH** | **YES** | `250-AUTH PLAIN LOGIN` |
| **STARTTLS** | **YES** | `250-STARTTLS` |
| **SIZE** | **YES** | `250-SIZE 52428800` |
| **Other** | **YES** | `250-PIPELINING`, `250 HELP` |

> **Evidence Checkpoint 5:** Screenshot showing the EHLO/HELO command and the server's capability response.

---

### 11. AUTH Exchange and Offline Base64 Decoding

```bash
# Locate likely AUTH packets
tshark -r ~/SBT-DF203-Lab4/working/smtp.pcap -Y 'smtp.request.command == "AUTH"' \
  -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.stream -e smtp.request.command -e smtp.request.parameter

# Offline decoding standard procedure:
printf '%s' 'VXNlcm5hbWU=' | base64 --decode

```

| Frame | AUTH mechanism | Encoded value (masked) | Decoded result (redacted) | Interpretation |
| --- | --- | --- | --- | --- |
| **10** | LOGIN | *(None)* | `AUTH LOGIN` | Client initiates LOGIN authentication method |
| **13** | LOGIN | `VXNlcm5hbWU=` | `Username:` | Server 334 prompt for username |
| **14** | LOGIN | `Z3Vy...LmLu` | `[REDACTED-USERNAME]` | Username base64 payload submitted by client |
| **15** | LOGIN | `UGFzc3dvcmQ=` | `Password:` | Server 334 prompt for password |
| **16** | LOGIN | `Z3Vy...LmLu` | `[REDACTED-PASSWORD]` | Password base64 payload submitted by client |

> **Evidence Checkpoint 6:** Screenshot of the offline decoding process with sensitive values masked/redacted.

---

### 12. MAIL FROM / RCPT TO / DATA

```bash
tshark -r ~/SBT-DF203-Lab4/working/smtp.pcap -Y \
  'smtp.request.command == "MAIL" || smtp.request.command == "RCPT" || smtp.request.command == "DATA"' \
  -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.stream -e smtp.request.command -e smtp.request.parameter

```

| Frame | Time | Command | Direction | Parameter / recipient | Response |
| --- | --- | --- | --- | --- | --- |
| **16** | Oct 5, 2009 02:06:09.614414 EDT | `MAIL FROM` | Client → Server | `FROM: <[REDACTED-SENDER]@patriots.in>` | `250 OK` |
| **18** | Oct 5, 2009 02:06:09.957250 EDT | `RCPT TO` | Client → Server | `TO: <[REDACTED-RECIPIENT]@yahoo.co.in>` | `250 Accepted` |
| **20** | Oct 5, 2009 02:06:10.320203 EDT | `DATA` | Client → Server | None | `354 Enter message...` |

> **Evidence Checkpoint 7:** Screenshot showing `MAIL FROM`, `RCPT TO`, and `DATA` in sequence.

---

### 13. Follow TCP Stream — Message Reconstruction

```bash
tshark -r ~/SBT-DF203-Lab4/working/smtp.pcap -Y 'tcp.stream == 0' \
  -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.seq -e tcp.ack -e tcp.len

```

| Field | Observation |
| --- | --- |
| **TCP stream** | 0 |
| **Client → server data** | `EHLO GP`<br>

<br>`AUTH LOGIN`<br>

<br>`[REDACTED-BASE64-USER]`<br>

<br>`[REDACTED-BASE64-PASS]`<br>

<br>`MAIL FROM: <[REDACTED-SENDER]@patriots.in>`<br>

<br>`RCPT TO: <[REDACTED-RECIPIENT]@yahoo.co.in>`<br>

<br>`DATA`<br>

<br>`[MIME Message Payload & Body Contents]`<br>

<br>`.`<br>

<br>`QUIT` |
| **Server → client data** | `220-xc90.websitewelcome.com ESMTP Exim 4.69...`<br>

<br>`250-xc90.websitewelcome.com Hello GP...`<br>

<br>`334 VXNlcm5hbWU=`<br>

<br>`334 UGFzc3dvcmQ=`<br>

<br>`235 Authentication succeeded`<br>

<br>`250 OK`<br>

<br>`250 Accepted`<br>

<br>`354 Enter message, ending with "." on a line by itself`<br>

<br>`250 OK id=1Mugho-0003Dg-Un`<br>

<br>`221 xc90.websitewelcome.com closing connection` |
| **Reconstruction successful** | **YES** |
| **Message body visible** | **YES** |

> **Evidence Checkpoint 8:** Follow TCP Stream screenshot showing the reconstructed SMTP exchange with sensitive data redacted.

---

### 14. Message Headers and Client Software

```bash
tshark -r ~/SBT-DF203-Lab4/working/smtp.pcap -Y smtp -T fields \
  -e frame.number -e tcp.stream -e data.data | grep -Ei 'Date:|From:|To:|Subject:|Message-ID|MIME|User-Agent|X-Mailer'

```

| Header / indicator | Observed value (redacted where necessary) | Evidence frame/stream |
| --- | --- | --- |
| **From** | `"Gurpartap Singh" <[REDACTED-SENDER]@patriots.in>` | Stream 0 |
| **To** | `<[REDACTED-RECIPIENT]@yahoo.co.in>` | Stream 0 |
| **Subject** | `SMTP` | Stream 0 |
| **Date** | `Mon, 5 Oct 2009 11:36:07 +0530` | Stream 0 |
| **Message-ID** | `<000301ca4581$ef9e57f0$cedb07d0$@in>` | Stream 0 |
| **MIME-Version** | `1.0` | Stream 0 |
| **Content-Type** | `multipart/mixed;` | Stream 0 |

> **Evidence Checkpoint 9:** Screenshot showing the message headers and client-software indicators.

---

### 15. SMTP Command / Response Timeline

| Order | Time | Direction | Command / response | Code | Evidence / significance |
| --- | --- | --- | --- | --- | --- |
| **1** | Oct 5, 2009 02:06:08.000 EDT | Server → Client | 220 Service Ready | 220 | Session start |
| **2** | Oct 5, 2009 02:06:08.224 EDT | Client → Server | `EHLO GP` | — | Client identification/capabilities |
| **3** | Oct 5, 2009 02:06:08.224 EDT | Server → Client | Capabilities | 250 | Advertises SIZE, PIPELINING, AUTH, STARTTLS |
| **4** | Oct 5, 2009 02:06:08.568 EDT | Client → Server | `AUTH LOGIN` | — | Initiates authentication |
| **5** | Oct 5, 2009 02:06:08.890 EDT | Server → Client | Authentication Succeeded | 235 | `235 Authentication succeeded` |
| **6** | Oct 5, 2009 02:06:09.614 EDT | Client → Server | `MAIL FROM` | — | Envelope sender transaction |
| **7** | Oct 5, 2009 02:06:09.614 EDT | Server → Client | MAIL Response | 250 | `250 OK` |
| **8** | Oct 5, 2009 02:06:09.957 EDT | Client → Server | `RCPT TO` | — | Envelope recipient transaction |
| **9** | Oct 5, 2009 02:06:09.957 EDT | Server → Client | RCPT Response | 250 | `250 Accepted` |
| **10** | Oct 5, 2009 02:06:10.320 EDT | Client → Server | `DATA` | — | Initiates message body transfer |
| **11** | Oct 5, 2009 02:06:10.320 EDT | Client → Server | Headers & Body | — | Transmission ends with `.` |
| **12** | Oct 5, 2009 02:06:10.320 EDT | Server → Client | DATA Response | 250 | Queued (`250 OK id=1Mugho-0003Dg-Un`) |
| **13** | Oct 5, 2009 02:06:10.320 EDT | Client → Server | `QUIT` | — | Session termination requested |

> **Evidence Checkpoint 10:** Screenshot or consolidated evidence table supporting the final SMTP timeline.

---

### 16. STARTTLS / TLS Assessment

```bash
tshark -r ~/SBT-DF203-Lab4/working/smtp.pcap -Y 'frame contains "STARTTLS"' \
  -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.stream -e data.data

tshark -r ~/SBT-DF203-Lab4/working/smtp.pcap -Y tls

```

| Item | Observed result |
| --- | --- |
| **STARTTLS command present** | **NO** |
| **STARTTLS response** | **N/A** (Capability advertised by server, but command was not issued by client) |
| **TLS handshake present** | **NO** |
| **TLS version** | **N/A** |
| **Certificate information visible** | **N/A** |
| **SMTP commands after TLS readable?** | **YES** (Session was entirely in cleartext) |
| **Message content after TLS readable?** | **YES** (Session was entirely in cleartext) |

> **Evidence Checkpoint 11:** Screenshot supporting the STARTTLS/TLS conclusion.

---

### 17. QUIT and Session Termination

```bash
tshark -r ~/SBT-DF203-Lab4/working/smtp.pcap -Y 'smtp.request.command == "QUIT"' \
  -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.stream -e smtp.request.command

```

| Frame | Time | Direction | Command | Server response | Interpretation |
| --- | --- | --- | --- | --- | --- |
| **23** | Oct 5, 2009 02:06:10.320203 EDT | Client → Server | `QUIT` | `221 xc90.websitewelcome.com closing connection` | Graceful session termination |

---

### 18. Quantitative Findings

| Measure | Observed value |
| --- | --- |
| **Total packets in PCAP** | 60 |
| **SMTP-related packets** | 32 |
| **TCP conversations** | 1 |
| **SMTP TCP streams** | 1 |
| **Distinct client IPs** | 1 (`10.10.1.4`) |
| **Distinct server IPs** | 1 (`74.53.140.153`) |
| **Email transactions identified** | 1 |
| **STARTTLS sessions** | 0 |
| **Plaintext SMTP sessions** | 1 |

---

### 19. Forensic Findings

| Finding | Evidence | Assessment |
| --- | --- | --- |
| **Email exchange time** | Oct 5, 2009 02:06:08 EDT – Oct 5, 2009 02:06:10 EDT | Transmission completed in approximately 2.095 seconds. |
| **SMTP client** | IP: `10.10.1.4` / Software: EHLO GP | Private network address acting as Mail User Agent / Client. |
| **SMTP server** | IP: `74.53.140.153` / Hostname: `xc90.websitewelcome.com` | Remote ESMTP Exim 4.69 mail server. |
| **Envelope sender** | `MAIL FROM: <[REDACTED-SENDER]@patriots.in>` | Validated sender domain matching message headers. |
| **Envelope recipient** | `RCPT TO: <[REDACTED-RECIPIENT]@yahoo.co.in>` | Validated target recipient address accepted by server (`250 Accepted`). |
| **Subject** | `Subject: SMTP` | Unencrypted message subject line. |
| **Authentication observed** | **YES** | Cleartext `AUTH LOGIN` method executed; credentials Base64 decoded and redacted. |
| **STARTTLS/TLS** | **NO** | Session remained unencrypted despite server advertising STARTTLS support. |
| **Message reconstruction** | **COMPLETE** | Full email message, headers, and body contents successfully extracted from stream 0. |

---

### 20. Evidential Limitations

* A packet capture is evidence of observed network traffic; it does not by itself prove who physically operated the client system.
* IP addresses identify network endpoints, not necessarily individual persons.
* MAC addresses may identify local interface addresses within the captured segment but do not establish legal ownership by a person.
* Base64 decoding reveals encoded data but does not provide cryptographic security.
* If STARTTLS/TLS had been negotiated, later SMTP commands and message content would be unavailable for plaintext reconstruction.
* A missing packet, truncated capture, or asymmetric capture point can prevent complete reconstruction.
* Redaction in this report intentionally hides sensitive credentials and personal message content; the preserved authorised evidence remains the source for verification.

---

### 21. Conclusion

The SMTP forensic investigation demonstrated a repeatable process for preserving packet captures, establishing evidence integrity via SHA-256 hashing, identifying client/server endpoints, parsing text-based SMTP commands and responses, decoding Base64 authentication structures offline, extracting message headers, and assessing protocol security states (STARTTLS/TLS). All conclusions in this report are based strictly on captured network packet evidence.
