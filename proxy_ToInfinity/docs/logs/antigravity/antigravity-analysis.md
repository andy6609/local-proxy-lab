# Antigravity App Network Analysis

## Overview
This document summarizes our attempt to intercept and dump the network traffic of the standalone **Antigravity** desktop app using our custom `proxy_ToInfinity` C++ MITM proxy on macOS.

## Testing Methodology
1. Enabled macOS System-wide HTTP/HTTPS proxy pointing to `127.0.0.1:18080`.
2. Restarted the Antigravity app completely.
3. Uploaded a file and attempted to chat to trigger network traffic.
4. Monitored the `proxy_ToInfinity` console logs and raw dumps.

## Findings & Defense Mechanisms
Despite the system-wide proxy being active, we **failed** to intercept the main payload (chat & file upload). We discovered that the Antigravity app utilizes a multi-layered defense architecture against MITM proxy interception.

### Defense 1: Proxy Bypass (Direct Connection)
The primary chat and file upload traffic completely bypassed the macOS System Proxy settings.
- The `proxy_ToInfinity` logs showed zero connection attempts for the main Antigravity backend domains.
- This suggests that the app's networking module (e.g., custom Node.js, Electron, or gRPC client) is configured to ignore the OS-level proxy settings and establish direct connections to the Google/Antigravity servers.

### Defense 2: Strict TLS Verification / Certificate Pinning
For secondary services that *did* attempt to route through the proxy (such as auto-updaters or telemetry, though the auto-updater itself successfully bypassed CA checks in one instance), we observed the following error in the proxy logs for other secure domains:
```
[ERROR] Client SSL_accept failed for [hostname] SSL_get_error=1 ERR=error:0A000126:SSL routines::unexpected eof while reading
```
**Analysis of the Error:**
- `unexpected eof while reading` occurs when the client abruptly closes the TCP connection during the TLS handshake.
- This happens right after the proxy sends its `ServerHello` along with the fake MITM certificate (signed by our custom Root CA).
- Even though our Root CA was added to the macOS Keychain, the Antigravity app (and other strict apps like `ios.chat.openai.com` and `gateway.icloud.com`) relies on its own **Custom Trust Store** or **Certificate Pinning**. 
- It immediately detects that the certificate is not signed by a genuine Google CA and aborts the connection before any HTTP headers or payloads are transmitted.

## Conclusion
The Antigravity standalone app cannot be casually intercepted using a standard OS proxy configuration. Intercepting its traffic would require:
1. Hard-patching the app's binary to disable Certificate Pinning / Trust Store validation (e.g., setting `NODE_TLS_REJECT_UNAUTHORIZED=0`).
2. Forcing traffic routing at the network interface layer (e.g., `pf` or iptables transparent proxying) rather than relying on OS HTTP proxy settings.
