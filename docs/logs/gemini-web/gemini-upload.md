# Gemini Web - File Upload Analysis

## Overview
Unlike Claude and ChatGPT which use standard `multipart/form-data` uploads to their respective AI APIs, **Google Gemini** uses Google's generic infrastructure for file uploads, specifically the **Google Resumable Upload Protocol**. 

Instead of uploading to a `gemini.google.com` endpoint, the file is routed to `push.clients6.google.com` using a two-step handshake.

## 1. Initializing the Upload (Start)
The first request initiates the session but does not contain the file data.
It is identifiable by the custom `x-goog-upload-command: start` header.

**Endpoint:** `POST /upload/`
**Host:** `push.clients6.google.com`

**Key Headers:**
```http
x-goog-upload-protocol: resumable
x-goog-upload-command: start
x-goog-upload-header-content-length: <Total File Size>
push-id: feeds/...
x-client-pctx: <Context Token>
```
*Note that the `content-length` of this initial request is very small (e.g., 25 bytes) because it only contains metadata/initialization data.*

## 2. Uploading the Data (Finalize)
Once initialized, the client receives an `upload_id` and makes a second `POST` request to actually transmit the raw binary data.

**Endpoint:** `POST /upload/?upload_id=<ID>&upload_protocol=resumable`
**Host:** `push.clients6.google.com`

**Key Headers:**
```http
x-goog-upload-command: upload, finalize
x-goog-upload-offset: 0
x-tenant-id: bard-storage
content-type: application/x-www-form-urlencoded;charset=utf-8
content-length: <Raw Binary Size>
```

### Observations & Fingerprinting
1. **No Multipart Boundaries:** The payload in the second request is raw bytes, not wrapped in any `--boundary` text.
2. **Tenant ID:** The header `x-tenant-id: bard-storage` is a dead giveaway that this file is destined for Gemini (formerly Bard), distinguishing it from Google Drive or YouTube uploads that use the same `push.clients6.google.com` infrastructure.
3. **Resumable Protocol:** The presence of `x-goog-upload-*` headers is the standard signature for Google's cloud storage services.

## Conclusion
Gemini's file upload is completely different from other LLM providers. To intercept or analyze Gemini uploads, the proxy must monitor `push.clients6.google.com` (or similar `*.clients*.google.com` domains) and parse the `x-goog-upload-command` sequence rather than looking for standard HTML forms.
