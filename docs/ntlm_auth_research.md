# NTLM Authentication in JavaScript/Node.js: Protocol, Libraries, HTTP Integration, Security, and Windows Integration

## Executive Summary and Scope

NTLM (NT LAN Manager) is a legacy, proprietary authentication protocol that remains widespread in enterprise environments, particularly for intranet web applications and systems still anchored to on‑premises Active Directory. While Kerberos has long been the preferred domain authentication mechanism, NTLM persists in many application stacks, often as a compatibility requirement or for server-to-server flows where no domain trust is available. In HTTP, NTLM’s challenge–response handshake is connection‑oriented and typically transported in Authorization and WWW‑Authenticate headers, which has important implications for client and server design in Node.js services and middleware[^1][^3].

This report synthesizes the protocol mechanics, the JavaScript/Node.js library landscape, secure client and server patterns, and integration with Windows authentication (SSPI, Active Directory). It concludes with a pragmatic migration path toward modern authentication.

Key findings:
- NTLM uses a three-message handshake (Type 1 negotiation, Type 2 challenge, Type 3 authentication) and, optionally, session security (signing and sealing). The HTTP scheme is connection-oriented and requires persistent connections; the API surface appears request‑oriented due to repeated 401 challenges[^1][^3].
- JavaScript libraries for NTLM cluster into client and server categories. httpntlm and axios‑ntlm are practical client choices; express‑ntlm and NodeSSPI enable server-side Windows authentication on Node.js. Maintenance quality and ecosystem support vary; axios‑ntlm is actively used, httpntlm is stable, and NodeSSPI is maintained on Windows[^5][^8][^10][^11][^13].
- Security weaknesses (LM/NTLMv1 weaknesses, relay/MitM) are well documented. Prefer NTLMv2 where possible, enforce TLS, manage keep‑alive carefully, and plan migration to OAuth/OpenID Connect (OIDC) for long‑term risk reduction[^15][^2][^3].
- Server-side Windows integration can be achieved via SSPI (NodeSSPI) or Active Directory–backed LDAP. These patterns are robust for intranet single sign‑on (SSO) but require careful operational guardrails. Azure AD/B2C provides a path to modernized authentication in cloud environments[^13][^14][^18][^19][^20].

Scope: HTTP NTLM flows in Node.js, JavaScript libraries, client/server implementation patterns, security considerations, Windows/AD integration, and migration to modern protocols.

Non-goals: Deep cryptographic proofs, comprehensive coverage of non‑HTTP protocols (e.g., SMTP/IMAP/POP3), and exhaustive review of deprecated or unmaintained libraries beyond widely used references.

## NTLM Protocol Fundamentals: Handshake, Messages, Flags, and Session Security

NTLM is a challenge–response protocol implemented via the NTLM Security Support Provider (NTLMSSP) within Microsoft’s Security Support Provider Interface (SSPI). It authenticates users and optionally provides message integrity (signing) and confidentiality (sealing) for subsequent application messages. Conceptually, three roles are involved: client, server, and domain controller (or local accounts for member servers)[^1][^2].

NTLM’s core handshake is tri‑partite:
- Type 1 (Negotiation): The client advertises capabilities and optionally supplies domain and workstation hints.
- Type 2 (Challenge): The server provides a challenge and target information (domain/host details), negotiating options.
- Type 3 (Authentication): The client proves knowledge of the password indirectly by sending LM/LMv2/NTLM/NTLMv2 responses and identity fields; session keys may be exchanged for subsequent signing/sealing[^1][^2].

Session security can be established after authentication, with older NTLM1 schemes and the NTLM2 session scheme providing different cryptographic properties. Session security is not always used in HTTP, but the model informs how signing/sealing would apply to other application protocols[^1][^2].

To illustrate the essential fields and negotiation semantics, Table 1 summarizes the NTLM message types and core structure fields.

Table 1: NTLM message types and core fields
| Message | Purpose | Key Fields | Notes |
|---|---|---|---|
| Type 1 (Negotiation) | Advertise client capabilities and context | Signature (“NTLMSSP”), MessageType=1, Flags; optional SuppliedDomain, SuppliedWorkstation, OS Version | Negotiates Unicode/OEM, request target, signing/sealing support, NTLM, datagram style, key strength, etc. |
| Type 2 (Challenge) | Provide server challenge and negotiate options | Signature, MessageType=2, TargetName, Flags, Challenge (8 bytes); optional Context, TargetInfo, OS Version | May include TargetInfo block for downstream NTLMv2 response construction and domain/host identification. |
| Type 3 (Authentication) | Respond to challenge; authenticate user | Signature, MessageType=3, LM/LMv2 Response, NTLM/NTLMv2 Response, TargetName, UserName, Workstation; optional SessionKey, Flags, OS Version | Identity fields may be NetBIOS (DOMAIN\\user) or DNS-style (domain.com\\user). SessionKey supports key exchange. |

These messages and their flags are described in detail by the canonical Davenport documentation, which also outlines the NTLMSSP structure and negotiation semantics[^1]. The Microsoft Learn overview complements this with a high‑level depiction of the call flow across application protocols[^2].

### Handshake and Message Flow

The handshake is connection-oriented. In HTTP, the client initially requests a resource, and the server responds with 401 and WWW‑Authenticate: NTLM, closing or reusing the connection depending on server policy. The client then resubmits the request with Authorization: NTLM <Base64(Type 1)>, the server replies 401 with WWW‑Authenticate: NTLM <Base64(Type 2)>, and the client resubmits the request with Authorization: NTLM <Base64(Type 3)>. After validation, the server returns 200 OK. Subsequent requests on the same connection do not carry authentication metadata because the connection itself is authenticated[^1].

Implications:
- Persistent connections are mandatory for HTTP NTLM. Proxies that multiplex requests across connections can cause spurious reauthentication cycles and failures.
- Redirection and authentication must be carefully coordinated; libraries must avoid following redirects during handshake steps to prevent token loss or confusion[^1].

For non‑HTTP protocols such as POP3/IMAP/SMTP, the same NTLM messages are conveyed in protocol‑specific command exchanges, but the underlying mechanics remain consistent with the three‑step challenge–response pattern[^1].

### Responses and Session Security

Legacy responses include LM, NTLM (NTLMv1), and NTLM2 session; modern responses include LMv2 and NTLMv2. LM and NTLMv1 have well‑documented weaknesses: LM’s case‑insensitive, DES‑based construction, and NTLMv1’s susceptibility to certain attack models. NTLMv2 and LMv2 use HMAC‑MD5 and incorporate a client nonce and timestamped blob, significantly improving resistance to precomputation and replay[^1].

Session security modes:
- NTLM1: Signing and sealing based on RC4 with keys derived from LM or NTLM user session keys; key weakening rules apply for export compliance.
- NTLM2 Session: A newer scheme negotiated with the NTLM2 Key flag; signing keys are full‑strength HMAC‑MD5 subkeys, while sealing keys can be weakened per negotiation (40/56/128 bits). The NTLM2 scheme reduces known plaintext exposure compared to NTLM1[^1].

Table 2 compares response types, security properties, and usage.

Table 2: NTLM response types and properties
| Response Type | Computation Summary | Strengths | Weaknesses | Typical Use |
|---|---|---|---|---|
| LM | Uppercased password → LM hash → DES encrypt challenge (3 keys) | Compatibility with ancient systems | Weak; case‑insensitive; half may be null | Legacy clients/servers |
| NTLM (v1) | MD4 of Unicode password → DES encrypt challenge (3 keys) | Better than LM; case‑sensitive | Still DES‑based; combined with LM in many flows | Legacy domain members |
| LMv2 | HMAC‑MD5(NTLM hash, uppercaseUser+Target) on (challenge + client nonce) | Better integrity; per‑session randomness | Slightly more overhead | With NTLMv2 or for compatibility |
| NTLMv2 | HMAC‑MD5(NTLM hash, uppercaseUser+Target) on (challenge + blob) | Strong against precomputation/replay; includes target info | Requires newer clients/servers | Preferred modern response |
| NTLM2 Session | Client nonce; MD5 on challenge+nonce to form session hash; NTLM response encrypts session hash | Mitigates dictionary attacks; better session properties | Requires NTLM2 support | When NTLMv2 not negotiated but NTLM2 session is supported |

These details, including the derivations of user session keys and Lan Manager session keys, are comprehensively covered in Davenport[^1].

### Datagram-Oriented vs Connection-Oriented Modes

NTLM supports a datagram style suitable for connectionless protocols and environments where the server advertises supported options rather than the client pre‑negotiating them. Datagram mode modifies the handshake, flags, and sequence handling compared to connection-oriented flows. In HTTP, the connection-oriented mode dominates; application teams should ensure the chosen library assumes persistent connections, not stateless request challenges[^1][^2].

## NTLM in HTTP for Node.js: How It Works in Practice

In HTTP, NTLM tokens are conveyed in the Authorization header on the client side and the WWW‑Authenticate header on the server side. The sequence comprises two 401 rounds with NTLM tokens, followed by success. The server and proxies must preserve the authenticated connection, and clients must not follow redirects during the handshake. NTLM also works for proxy authentication using 407 and Proxy‑Authorization/Proxy‑Authenticate headers[^1].

Connection orientation matters. NTLM authenticates a connection, not an individual HTTP request. On the same authenticated connection, subsequent requests reuse the authentication without further WWW‑Authenticate negotiation. Proxies that round‑robin or break keep‑alive can force repeated handshakes or cause failure. Keep‑alive agents and careful timeout configuration are therefore critical on both client and server[^1].

For developers, the main practical considerations are:
- Ensuring the HTTP client reuses connections and tolerates the 401 challenges without redirecting.
- Managing keep‑alive agents (HTTP/HTTPS) to amortize handshake costs.
- Coordinating proxy behavior; avoid proxies that fragment connections or change users mid‑stream.
- Handling binary responses; the client must respect content‑type and encoding, and avoid corrupting binary payloads during NTLM negotiation[^1].

### Connection Management and Keep‑Alive

Node.js clients should reuse sockets via keep‑alive agents. Libraries like axios‑ntlm automatically attach keep‑alive agents when none are provided, but they also allow custom agents for tighter control. Reusing agents minimizes repeated three‑step handshakes and reduces latency on subsequent requests[^8][^10]. On the server, adjust timeouts and maximum requests per socket so that idle connections do not drop mid‑handshake and authenticated connections are not prematurely closed[^9].

## JavaScript/Node.js Library Landscape: Client and Server Options

Node.js practitioners have several library options for NTLM. The choices largely hinge on whether the application acts as a client or a server, and how deeply it needs to control the handshake and session behavior.

Client libraries:
- httpntlm: A mature client library offering direct NTLM message functions (createType1Message, parseType2Message, createType3Message) and support for NTLMv2. It can be used directly or through httpreq. Examples include GET/POST flows, pre‑encrypted LM/NT hashes, and binary downloads[^5][^6][^7].
- axios‑ntlm: A helper library that wraps an Axios instance and attaches interceptors to manage the NTLM handshake. It automatically sets keep‑alive agents and allows custom Axios configuration, making it ergonomically appealing for REST clients[^8][^10][^11].
- jsntlm: A basic NTLM implementation with a focus on challenge–response and proxy scenarios. It is less feature‑rich and appears infrequently maintained[^12].
- node‑client‑ntlm: A client library supporting NTLM v1/v2 and HTTP methods; less commonly referenced but provides another implementation path[^17].
- npm search shows additional packages (e.g., @ewsjs/ntlm‑client, request‑ntlm‑promise, httpntlm). However, this report focuses on the well‑documented libraries above[^16].

Server libraries:
- express‑ntlm: Express middleware for NTLM with options to validate users against Active Directory via LDAP/LDAPS, configurable error handling, and debug logging. Without a domain controller configured, it can operate in a non‑validating mode, which is strongly discouraged for production[^13].
- NodeSSPI: A native Windows module that performs SSPI‑based Windows authentication (NTLM and Negotiate). It exposes the authenticated user, SID, and optional group memberships on the request object and offers detailed constructor options. It is Windows‑only and only tested with NTLM and Negotiate; Kerberos support is noted as not working[^14].

Table 3 compares features and maturity signals across widely used libraries.

Table 3: Feature matrix of NTLM libraries in the Node.js ecosystem
| Library | Role | NTLM Support | NTLMv2 | Keep‑Alive Handling | Notable Features | License | Maintenance Snapshot |
|---|---|---|---|---|---|---|---|
| httpntlm | Client | NTLMv1, NTLMv2 | Yes | Via httpreq or custom agents | Direct NTLM message APIs; binary downloads; pre‑encrypted hashes | MIT | Stable, last commit in 2023[^5][^7] |
| axios‑ntlm | Client (Axios) | NTLM | Yes (via underlying client) | Auto agents if not provided; supports custom agents | Interceptors automate handshake; supports Axios config | MIT | Actively used; last publish ~2 months prior to analysis[^8][^10][^11] |
| jsntlm | Client | Basic NTLM | Not emphasized | Not specified | Proxy examples; minimal | — | Low activity; last commit 2017[^12] |
| node‑client‑ntlm | Client | NTLM v1/v2 | Yes | Not specified | HTTP client with NTLM; method support | — | Unclear; package page shows basic info[^17] |
| express‑ntlm | Server (Express) | NTLM | Yes (where supported by OS) | Connection‑oriented behavior | AD/LDAP validation; custom error handling; debug; cache hooks | BSD‑2 | Publish history shows 2+ years since last update[^13] |
| NodeSSPI | Server (Windows) | NTLM/Negotiate (SSPI) | OS‑dependent | Connection‑level auth; per‑request option | Retrieves user, SID, groups; Windows‑only; detailed options | MIT | Maintained; last commit Nov 2024[^14] |

The choice between httpntlm and axios‑ntlm is often a matter of client ergonomics. The former gives low‑level control; the latter blends seamlessly with RESTful Axios workflows and connection management.

### Client Libraries (httpntlm, axios‑ntlm, jsntlm, node‑client‑ntlm)

For complex flows or custom control, httpntlm’s message APIs are valuable. For example, a custom two‑step pattern constructs Type 1, captures Type 2 from WWW‑Authenticate, and then constructs Type 3 before making the final request. This approach can be integrated with async waterfall patterns and keep‑alive agents, with guidance provided in the library’s examples[^5][^7].

Axios‑ntlm fits modern HTTP clients built on Axios. It accepts credentials (username, password, domain) and optional Axios configuration, attaches interceptors to manage the handshake, and handles connection keep‑alive. The library’s documentation emphasizes Node‑only usage and agent management, which simplifies session reuse across requests[^8][^10][^11].

Jsntlm and node‑client‑ntlm exist as alternatives. Jsntlm’s basic model and infrequent maintenance make it suitable primarily for simple proxy scenarios or experimentation. Node‑client‑ntlm advertises NTLM v1/v2 support but is less referenced in community guides; teams should evaluate it on its own merits (tests, issues, maintenance cadence) before adopting[^12][^17].

### Server Middleware (express‑ntlm, NodeSSPI)

Express‑ntlm supports basic NTLM server‑side authentication for Express applications. It can validate credentials via an Active Directory domain controller using LDAP or LDAPS (with custom TLS options for corporate CAs), exposes parsed NTLM fields (DomainName, UserName, Workstation) via request locals, and offers hooks to customize connection IDs and caching. It explicitly warns that proxies can break connection-oriented authorization and recommends either configuring keep‑alive or avoiding proxies in the path[^13].

NodeSSPI leverages Windows SSPI for server-side integrated authentication. It supports NTLM and Negotiate, can retrieve the user SID and group memberships, and exposes authenticated identity on the Node request. It is Windows‑only and, per project notes, does not currently support Kerberos; configuration options allow authoritative enforcement, per‑request auth, and group retrieval behavior, with clear caveats about AD performance when retrieving groups on every request[^14].

## Security Considerations and Best Practices

NTLM’s age and design come with inherent risks. The protocol has known weaknesses, notably around the LM and NTLMv1 responses, and is susceptible to relay and man‑in‑the‑middle attacks under certain conditions. Its connection-oriented HTTP behavior also introduces operational pitfalls when proxies or load balancers break keep‑alive or when clients mis-handle 401 challenges[^15][^1][^3].

Table 4 enumerates the common threats and pragmatic mitigations in Node.js environments.

Table 4: NTLM threats and mitigations
| Threat | Description | Mitigations |
|---|---|---|
| Relay attacks | Intercepted NTLM messages can be relayed to impersonate users | Enforce TLS on all links; consider disabling NTLM where relay risk is high; prefer modern protocols (Kerberos/OIDC) in greenfield designs[^15][^3] |
| Man‑in‑the‑Middle (MitM) | Attacker alters traffic between client and server | Enforce TLS with strict certificate validation; avoid mixed content; consider HSTS; avoid insecureHTTPParser[^9] |
| Brute force / dictionary | Weak LM/NTLMv1 responses susceptible to cracking | Prefer NTLMv2/LMv2; ensure strong password policies; avoid LM responses; keep systems at LMCompatibilityLevel that disables LM/NTLMv1[^1][^15] |
| Credential exposure | Passwords or hashes mishandled in logs or memory | Never log raw credentials; use pre‑encrypted hashes with caution; clear memory buffers; adopt secure coding practices[^9] |
| Proxy mixing users | Connection-oriented auth can be disrupted by proxies | Configure proxies for keep‑alive and stickiness; consider bypassing proxies for NTLM paths or authenticating proxies with shared session stores[^13] |
| DoS via resource exhaustion | Excessive connections or slow requests | Configure timeouts, request limits, and socket caps; place a reverse proxy in front; disable debug inspector in production[^9] |
| Request smuggling | Ambiguous HTTP request parsing | Avoid insecureHTTPParser; normalize upstream/downstream behavior; prefer HTTP/2 end‑to‑end[^9] |
| Supply chain risks | Compromised dependencies | Pin versions; use lockfiles; run npm audit; disable install scripts; review dependencies and package metadata[^9] |

Node.js platform guidance also provides specific configurations that harden servers against these risks, including server timeouts, secure heap, and policy mechanisms to constrain module loading and integrity[^9].

### Mitigations and Operational Guardrails

Prioritize NTLMv2 in all client configurations and ensure server-side settings do not permit downgrade to LM/NTLMv1. Enforce TLS on all endpoints, validate certificates, and avoid mixed HTTP/HTTPS paths. Harden HTTP servers with request and socket limits, carefully tuned timeouts, and reverse proxies to absorb DoS traffic. Finally, align library choices and connection strategies with the connection-oriented nature of NTLM, particularly in the presence of proxies and load balancers[^1][^9][^13].

## Integration Patterns with Windows Authentication

Node.js applications can participate in Windows integrated authentication using SSPI on Windows or by validating users and groups against Active Directory via LDAP. Azure AD/B2C offers a modern cloud‑native path.

- NodeSSPI (SSPI): Windows‑only SSPI integration supporting NTLM and Negotiate. It authenticates users, retrieves SID and optionally group memberships, and exposes the identity on the request object. It is best suited to intranet apps on domain‑joined hosts where integrated Windows SSO is the goal[^14].
- Active Directory via LDAP/LDAPS: express‑ntlm can validate users against AD by contacting domain controllers. It exposes NTLM fields to the application and supports LDAPS with custom TLS options for corporate CAs. It offers caching hooks and is designed for environments without proxies; upstream proxies must preserve keep‑alive or be excluded from the auth path[^13].
- Azure AD/B2C: For cloud‑aligned applications, configure Azure AD/B2C with modern protocols (OIDC/OAuth 2.0). Microsoft provides end‑to‑end guidance and sample configurations for Node.js web apps and APIs, which is the strategic direction for long‑term security and interoperability[^18][^19][^20].

### Active Directory Validation with express‑ntlm

Express‑ntlm provides middleware hooks for AD validation, exposing request.ntlm with fields such as DomainName, UserName, and Workstation. It can be configured to contact ldap:// or ldaps:// domain controllers, with tlsOptions enabling custom CA certificates for LDAPS. It also offers custom error handlers and debug logging. Caching hooks for user data support tailored strategies to reduce AD round trips[^13].

### SSPI Integration with NodeSSPI

NodeSSPI integrates with Windows SSPI to deliver integrated authentication and identity artifacts. It exposes req.connection.user, req.connection.userSid, and optionally req.connection.userGroups upon success. Its constructor supports options like authoritative enforcement, per‑request authentication, SSPI package selection (NTLM/Negotiate), and group retrieval behavior (with caution for AD performance). It is Windows‑only and explicitly does not support Kerberos per project notes[^14].

## Implementation Examples and Code Patterns

The following patterns illustrate practical implementations using popular libraries and secure server configuration. They are minimal examples intended to be adapted for production with the operational guardrails discussed earlier.

Client: httpntlm with manual Type 1/2/3 flow and keep‑alive
```javascript
// npm install httpntlm httpreq agentkeepalive
var httpntlm = require('httpntlm');
var ntlm = httpntlm.ntlm;
var httpreq = require('httpreq');
var HttpsAgent = require('agentkeepalive').HttpsAgent;
var keepaliveAgent = new HttpsAgent();

var options = {
  url: 'https://protected.example.com/resource',
  username: 'alice',
  password: 'Secret!',
  workstation: 'CLIENT01',
  domain: 'CORP'
};

async function run() {
  // Step 1: Send Type 1
  const type1 = ntlm.createType1Message(options);
  const res1 = await httpreq.get(options.url, {
    headers: { Connection: 'keep-alive', Authorization: type1 },
    agent: keepaliveAgent,
    allowRedirects: false
  });

  // Step 2: Parse Type 2 and send Type 3
  if (!res1.headers['www-authenticate']) {
    throw new Error('Expected WWW-Authenticate header in Type 2 response');
  }
  const type2 = ntlm.parseType2Message(res1.headers['www-authenticate']);
  const type3 = ntlm.createType3Message(type2, options);

  // Step 3: Final request with authenticated connection
  const res2 = await httpreq.get(options.url, {
    headers: { Connection: 'Close', Authorization: type3 },
    allowRedirects: false,
    agent: keepaliveAgent
  });

  console.log('Status:', res2.statusCode);
  console.log('Body:', res2.body);
}
run().catch(console.error);
```
This pattern demonstrates direct control over the handshake and explicit keep‑alive agent reuse, reducing handshake overhead on subsequent calls[^5][^7].

Client: axios‑ntlm for a quick Axios‑based NTLM client
```javascript
// npm i axios axios-ntlm
import { NtlmClient } from 'axios-ntlm';

const credentials = {
  username: 'alice',
  password: 'Secret!',
  domain: 'CORP'
};

// The client manages interceptors and keep-alive agents.
const client = NtlmClient(credentials, {
  baseURL: 'https://protected.example.com',
  method: 'get',
  timeout: 10000
});

async function getResource() {
  try {
    const resp = await client.get('/api/resource');
    console.log(resp.data);
  } catch (err) {
    console.error('Request failed', err?.message);
  }
}
getResource();
```
This approach integrates NTLM transparently with Axios, allowing standard REST usage while the library handles the 401 challenge sequence and connection reuse[^8][^10][^11].

Server: Express with express‑ntlm and AD validation
```javascript
// npm install express express-ntlm
const express = require('express');
const ntlm = require('express-ntlm');

const app = express();

app.use(ntlm({
  debug: (...args) => console.log('[express-ntlm]', ...args),
  domain: 'CORP',
  domaincontroller: 'ldaps://dc.corp.example', // Custom CA if needed via tlsOptions
  tlsOptions: {
    // ca: fs.readFileSync('./corp-ca.pem')
  }
}));

app.all('*', (req, res) => {
  // { DomainName, UserName, Workstation }
  res.json(req.ntlm);
});

app.listen(3000, () => console.log('NTLM server listening on :3000'));
```
Configure proxies to preserve keep‑alive and avoid breaking connection-oriented authentication. Use LDAPS with proper certificate trust for production[^13].

Server: Secure Node.js HTTP server settings relevant to NTLM
```javascript
// Example server hardening (not NTLM-specific)
const http = require('http');

const server = http.createServer(app);

// Tune timeouts and request limits
server.headersTimeout = 15000;     // Max time to receive headers
server.requestTimeout = 30000;     // Max time to receive full request
server.timeout = 10000;            // Idle socket timeout
server.keepAliveTimeout = 15000;   // Keep-alive after last request
server.maxRequestsPerSocket = 100; // Close after N requests

// Example agent caps for outbound requests (clients)
// const agent = new http.Agent({ maxSockets: 50, maxTotalSockets: 200, maxFreeSockets: 10 });

server.listen(8080);
```
These settings align with Node.js security best practices and help prevent DoS and resource exhaustion while supporting NTLM’s connection orientation[^9].

Axios client: Using axios‑ntlm with custom Axios configuration and agents
```javascript
// npm i axios axios-ntlm
import { NtlmClient, NtlmCredentials } from 'axios-ntlm';
import { Agent } from 'http';

const credentials = { username: 'alice', password: 'Secret!', domain: 'CORP' };
const agent = new Agent({ keepAlive: true, maxSockets: 50 });

const client = NtlmClient(credentials, {
  baseURL: 'https://protected.example.com',
  httpsAgent: agent,
  headers: { 'X-Client': 'my-ntlm-service' }
});

async function fetchApi(path) {
  const resp = await client.get(path, { timeout: 10000 });
  return resp.data;
}
```
Custom agents can be provided to coordinate with connection pooling policies. When agents are omitted, axios‑ntlm sets keep‑alive agents automatically[^8][^10].

## Decision Guide: NTLM, Kerberos/OIDC, and Migration Path

When to use NTLM in 2025:
- Existing intranet applications with strict compatibility requirements against on‑premises Active Directory.
- Server‑to‑server or automation flows that do not have a Kerberos trust path.
- Client libraries and middleware already in place and operationally hardened.

When to prefer modern protocols:
- Internet‑facing applications and APIs requiring robust, interoperable authentication and delegated access.
- Scenarios needing federated identity, strong multi‑factor authentication, and centralized policy control.
- Long‑term risk management where NTLM’s legacy weaknesses and operational constraints are no longer acceptable[^15][^2].

Migration steps:
- Introduce an identity broker or gateway supporting OAuth 2.0 and OpenID Connect (OIDC). Azure AD/B2C provides a straightforward path for apps and APIs.
- Dual‑run and profile usage; gradually shift clients and services to OIDC endpoints.
- Harden the environment: enforce TLS, update client libraries, and monitor authentication telemetry.
- Decommission NTLM dependencies once parity is achieved and risk is acceptable[^18][^19][^20][^15].

Table 5 summarizes the trade‑offs.

Table 5: Protocol trade-offs—NTLM vs Kerberos/OIDC
| Protocol | Strengths | Constraints | Ideal Scenarios |
|---|---|---|---|
| NTLM | Simple challenge–response; widely deployed; works without domain trust | Legacy weaknesses; connection-oriented HTTP; proxy challenges; limited advanced features | Legacy intranet; server-to-server with no trust path |
| Kerberos | Strong authentication; delegated access; industry standard in domains | Requires domain trust and ticket granting; configuration complexity | Domain-joined environments; SSO with resource delegation |
| OIDC (OAuth 2.0) | Modern web security; federation; MFA; broad ecosystem | Requires identity provider setup; token lifecycle management | Internet-facing apps/APIs; cloud and hybrid environments |

These decisions should be driven by a risk assessment and an architectural plan that recognizes both the current operational reality and the target state.

## Appendix: Glossary, References, and Further Reading

Glossary:
- NTLMSSP: The NTLM Security Support Provider, the core protocol implementation within SSPI that handles authentication, message integrity, and confidentiality.
- SSPI: Security Support Provider Interface, a Windows API for security contexts, credentials, and authentication packages (NTLM, Kerberos, etc.).
- WWW‑Authenticate: HTTP response header indicating authentication methods offered by the server.
- Authorization: HTTP request header carrying client authentication tokens (e.g., NTLM messages Base64‑encoded).
- Type 1/2/3: NTLM Negotiation, Challenge, and Authentication messages.
- Signing/Sealing: Message integrity and confidentiality protections applied to application data after authentication.

Information gaps:
- Formal field‑level message structures for Type 1/2/3 from the full [MS‑NLMP] specification were not fully accessible in this analysis.
- Up‑to‑date maintenance and security posture for every package surfaced by npm search could not be validated beyond the examined libraries.
- Organization‑specific proxy and load balancer configurations (e.g., Nginx/HAProxy keep‑alive/connection reuse) are out of scope.
- Concrete deployment playbooks for integrating Node.js behind IIS/Apache with mod‑auth‑sspi were not compiled here.
- Performance benchmarks comparing libraries under high concurrency were not available in the sources.

References:
[^1]: The NTLM Authentication Protocol and Security Support Provider. https://davenport.sourceforge.net/ntlm.html  
[^2]: [MS-NLMP]: NTLM Authentication Call Flow. https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/1bf72e97-a970-482d-90fc-776732fea1be  
[^3]: NTLM Explained: Definition, Protocols & More | CrowdStrike. https://www.crowdstrike.com/en-us/cybersecurity-101/identity-protection/windows-ntlm/  
[^4]: Node.js module to authenticate using HTTP NTLM - GitHub. https://github.com/SamDecrock/node-http-ntlm  
[^5]: httpntlm - npm. https://www.npmjs.com/package/httpntlm  
[^6]: python-ntlm - Google Code. https://code.google.com/p/python-ntlm/  
[^7]: Snyk Advisor: httpntlm examples. https://snyk.io/advisor/npm-package/httpntlm/example  
[^8]: axios-ntlm - npm. https://www.npmjs.com/package/axios-ntlm  
[^9]: Node.js — Security Best Practices. https://nodejs.org/en/learn/getting-started/security-best-practices  
[^10]: axios-ntlm - GitHub. https://github.com/catbuttes/axios-ntlm  
[^11]: axios-ntlm homepage. https://buttes.dev/axios-ntlm/  
[^12]: Sage-ERP-X3/jsntlm - GitHub. https://github.com/Sage-ERP-X3/jsntlm  
[^13]: express-ntlm - npm. https://www.npmjs.com/package/express-ntlm  
[^14]: NodeSSPI: Server-side Windows authentication for Node.js - GitHub. https://github.com/abbr/NodeSSPI  
[^15]: Insecure authentication method - NTLM - Fluid Attacks. https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-typescript-388  
[^16]: npm search: ntlm. https://www.npmjs.com/search?q=ntlm  
[^17]: node-client-ntlm - npm. https://www.npmjs.com/package/node-client-ntlm  
[^18]: Configure authentication in a sample Node.js web API by using Azure AD B2C. https://learn.microsoft.com/en-us/azure/active-directory-b2c/configure-authentication-in-sample-node-web-app-with-api  
[^19]: Configure authentication in a sample Node.js web application by using Azure AD B2C. https://learn.microsoft.com/en-us/azure/active-directory-b2c/configure-a-sample-node-web-app  
[^20]: Use LDAP and Active Directory to authenticate Node.js users - IBM Developer. https://developer.ibm.com/tutorials/se-use-ldap-authentication-authorization-nodejs-cloud-application/  

Further reading:
- The Innovation Alley NTLM scheme overview remains a useful companion to Davenport for HTTP-specific details and target information handling[^1].  
- For SSPI integration on Windows, NodeSSPI’s documentation and issue tracker provide practical insights into configuration and limitations, especially around group retrieval and Kerberos support[^14].  
- Node.js security best practices consolidate platform-level controls (timeouts, policy, supply chain) that complement protocol‑level hardening in production environments[^9].