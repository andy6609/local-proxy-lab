/*
=============================================================
    Local Proxy 전체 구조 - 수도 코드 (Pseudocode)
=============================================================

최종 목표:
    브라우저가 ChatGPT에 파일 업로드할 때
    → 트래픽 가로채서
    → HTTPS 복호화해서
    → 파일 업로드 탐지

전체 흐름:
    브라우저 → [우리 Proxy] → ChatGPT 서버
                    ↑
              여기서 분석
=============================================================
*/


/* =========================================================
   STEP 1: TCP 서버 뼈대 (TCPserver.c)
   브라우저 연결을 받는 서버 역할
   ========================================================= */

   /*
   WSAStartup()            // Winsock 초기화

   SOCKET serverSock = socket()    // 서버 소켓 생성

   // 포트 8080 등록
   sockaddr_in serverAddr
   serverAddr.port = 8080
   bind(serverSock, serverAddr)    // "나 8080 포트 쓸게"

   listen(serverSock)              // 연결 대기 시작

   while (true) {
       SOCKET clientSock = accept(serverSock)  // 브라우저 연결 수락

       char buffer[4096]
       recv(clientSock, buffer)    // 브라우저가 보낸 데이터 받기

       send(clientSock, "Hello from server!")  // 응답

       closesocket(clientSock)
   }

   closesocket(serverSock)
   WSACleanup()
   */


   /* =========================================================
      STEP 2: Proxy 뼈대 (proxy.c)
      클라이언트 + 서버 역할 동시에
      브라우저 연결 받고 → 실제 서버로 중계
      ========================================================= */

      /*
      // 서버 소켓 열기 (브라우저한테는 서버 역할)
      SOCKET proxySock = socket()
      bind(proxySock, 8080)
      listen(proxySock)

      while (true) {
          // 브라우저 연결 수락
          SOCKET clientSock = accept(proxySock)

          // 브라우저 요청 받기
          char request[4096]
          recv(clientSock, request)

          // 실제 서버에 연결 (서버한테는 클라이언트 역할)
          SOCKET serverSock = socket()
          connect(serverSock, "chatgpt.com:80")

          // 브라우저 요청을 실제 서버로 전달
          send(serverSock, request)

          // 서버 응답 받기
          char response[4096]
          recv(serverSock, response)

          // 서버 응답을 브라우저로 전달
          send(clientSock, response)

          closesocket(serverSock)
          closesocket(clientSock)
      }
      */


      /* =========================================================
         STEP 3: HTTP 파싱 로직
         받은 데이터에서 HTTP 구조 분석
         ========================================================= */

         /*
         // 브라우저가 보낸 HTTP 요청:
         // POST /upload HTTP/1.1
         // Host: chatgpt.com
         // Content-Type: multipart/form-data; boundary=----abc123
         // Content-Length: 12345
         //
         // ------abc123
         // Content-Disposition: form-data; name="file"; filename="secret.pdf"
         // ...바이너리 데이터...

         void parseHTTP(char* request) {

             // 1. 첫 번째 줄 파싱 (요청 라인)
             // "POST /upload HTTP/1.1"
             char method[10]     // GET, POST, CONNECT 등
             char url[256]       // /upload
             char version[10]    // HTTP/1.1

             sscanf(request, "%s %s %s", method, url, version)

             // 2. 헤더 파싱
             // 빈 줄(\r\n\r\n) 전까지가 헤더
             char* headerEnd = strstr(request, "\r\n\r\n")

             // Host 헤더 찾기
             char* hostHeader = strstr(request, "Host: ")
             // → chatgpt.com

             // Content-Type 헤더 찾기
             char* contentType = strstr(request, "Content-Type: ")
             // → multipart/form-data; boundary=----abc123

             // 3. 메서드 확인
             if (strcmp(method, "POST") == 0) {
                 // POST 요청이면 파일 업로드일 수 있음
                 checkFileUpload(request, contentType)
             }

             // 4. CONNECT 메서드면 HTTPS 터널 요청
             if (strcmp(method, "CONNECT") == 0) {
                 // TLS MITM 처리
                 handleTLSMITM(clientSock, url)
             }
         }
         */


         /* =========================================================
            STEP 4: TLS MITM 로직
            HTTPS 복호화
            핵심: 브라우저↔Proxy, Proxy↔서버 두 개의 TLS 세션
            ========================================================= */

            /*
            // 브라우저가 CONNECT 요청 보냄:
            // "CONNECT chatgpt.com:443 HTTP/1.1"
            // → "야 chatgpt.com으로 HTTPS 터널 뚫어줘"

            void handleTLSMITM(SOCKET clientSock, char* host) {

                // 1. 브라우저한테 "터널 뚫었어" 응답
                send(clientSock, "HTTP/1.1 200 Connection Established\r\n\r\n")

                // 2. 실제 서버에 먼저 TLS 연결
                // → 진짜 인증서 확인
                SOCKET serverSock = connect("chatgpt.com:443")
                SSL* serverSSL = SSL_connect(serverSock)     // OpenSSL 사용
                // → 실제 chatgpt.com 인증서 받음

                // 3. host에 맞는 가짜 인증서 만들기
                // → Root CA로 서명한 chatgpt.com 인증서 생성
                X509* fakeCert = createFakeCert(host, rootCA)
                // → 브라우저가 이 인증서 신뢰하려면
                //   Root CA가 브라우저 trust store에 등록되어 있어야 함

                // 4. 브라우저와 TLS 세션 수립
                // → 가짜 인증서 제시
                SSL* clientSSL = SSL_accept(clientSock, fakeCert)

                // 5. 이제 양쪽 TLS 세션 다 수립됨
                // 브라우저 ↔ [clientSSL] ↔ Proxy ↔ [serverSSL] ↔ chatgpt.com

                while (true) {
                    // 브라우저가 보낸 암호화 데이터 복호화
                    char plaintext[4096]
                    SSL_read(clientSSL, plaintext)
                    // → 이제 평문 HTTP 데이터 볼 수 있음!

                    // HTTP 파싱 (파일 업로드 탐지)
                    parseHTTP(plaintext)

                    // 서버로 다시 암호화해서 전달
                    SSL_write(serverSSL, plaintext)

                    // 서버 응답 받아서 브라우저로 전달
                    char response[4096]
                    SSL_read(serverSSL, response)
                    SSL_write(clientSSL, response)
                }
            }
            */


            /* =========================================================
               STEP 5: 파일 업로드 탐지 로직
               HTTP 파싱 후 파일 업로드 여부 확인
               ========================================================= */

               /*
               // 파일 업로드 HTTP 요청 생김새:
               //
               // POST /upload HTTP/1.1
               // Content-Type: multipart/form-data; boundary=----abc123
               //
               // ------abc123
               // Content-Disposition: form-data; name="file"; filename="secret.pdf"
               // Content-Type: application/pdf
               //
               // (바이너리 데이터 시작)
               // %PDF-1.4....
               // (바이너리 데이터 끝)
               // ------abc123--

               void checkFileUpload(char* request, char* contentType) {

                   // 1. Content-Type이 multipart/form-data 인지 확인
                   if (strstr(contentType, "multipart/form-data") == NULL) {
                       return  // 파일 업로드 아님
                   }

                   // 2. boundary 값 추출
                   // "multipart/form-data; boundary=----abc123"
                   //                                ↑ 여기서부터
                   char boundary[100]
                   extractBoundary(contentType, boundary)
                   // boundary = "----abc123"

                   // 3. Body에서 파일 파트 찾기
                   char* body = strstr(request, "\r\n\r\n") + 4  // 헤더 끝 다음부터

                   // 4. boundary로 파트 분리
                   char* part = strstr(body, boundary)

                   while (part != NULL) {
                       // 5. Content-Disposition 헤더에서 파일명 추출
                       // "Content-Disposition: form-data; name="file"; filename="secret.pdf""
                       char filename[256]
                       extractFilename(part, filename)

                       if (strlen(filename) > 0) {
                           // 6. 파일 업로드 탐지!
                           printf("파일 업로드 탐지: %s\n", filename)

                           // 7. 파일 메타데이터 추출
                           char mimeType[100]
                           extractContentType(part, mimeType)  // application/pdf

                           int fileSize = extractFileSize(part)

                           // 8. 바이너리 데이터 추출
                           // boundary 다음 빈줄 이후부터 다음 boundary 전까지
                           char* binaryStart = strstr(part, "\r\n\r\n") + 4
                           char* binaryEnd = strstr(binaryStart, boundary) - 2
                           int binarySize = binaryEnd - binaryStart

                           // 9. 파일 시그니처 확인 (8주차)
                           // PDF: %PDF
                           // ZIP: PK
                           // EXE: MZ
                           checkFileSignature(binaryStart)

                           // 10. 로그 기록
                           logFileUpload(filename, mimeType, fileSize)

                           // 11. 정책에 따라 차단 또는 허용
                           if (isBlockedFileType(mimeType)) {
                               // 차단!
                               return BLOCK
                           }
                       }

                       // 다음 파트로
                       part = strstr(part + 1, boundary)
                   }
               }
               */


               /* =========================================================
                  전체 proxy.c 구조 요약
                  ========================================================= */

                  /*
                  main()
                  │
                  ├── WSAStartup()
                  ├── 포트 8080 열기 (bind, listen)
                  │
                  └── while(true) {
                          clientSock = accept()       // 브라우저 연결 수락

                          recv(request)               // 브라우저 요청 받기

                          parseHTTP(request)          // HTTP 파싱
                          │
                          ├── GET/POST?
                          │   └── HTTP면 → 그냥 중계
                          │
                          └── CONNECT?
                              └── HTTPS면 → TLS MITM
                                  │
                                  ├── 가짜 인증서 만들기
                                  ├── 브라우저와 TLS 세션
                                  ├── 서버와 TLS 세션
                                  └── 복호화된 HTTP 분석
                                      └── checkFileUpload()
                                          ├── multipart/form-data?
                                          ├── 파일명 추출
                                          ├── 바이너리 추출
                                          └── 탐지/차단/로그
                      }
                  */