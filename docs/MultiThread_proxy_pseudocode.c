// main.cpp

void HandleClient(SOCKET clientSock) {
    // =================================================================
    // [이번 주 스텝 3의 무대] : 독립된 스레드 안에서 각자 소켓을 전담 마크함
    // =================================================================
    
    // 1. 브라우저 요청 읽기 (수도코드 STEP 2의 recv)
    char request[4096];
    recv(clientSock, request, ...);

    // 2. 호스트 파싱 (이번 주 스텝 3의 파싱 일부 + 수도코드 STEP 3)
    // "Host: httpbin.org"를 찾아내서 원본 서버 주소 획득!
    char targetIP[100] = "223.130.192.247"; // 임시 네이버 IP 하드코딩 가능

    // 3. 실제 서버에 연결 (수도코드 STEP 2의 connect)
    SOCKET serverSock = socket(...);
    connect(serverSock, targetIP, 80);

    // 4. 양방향 릴레이 링 가동 (이번 주 스텝 3의 핵심 릴레이)
    // 브라우저가 준 거 -> 서버로 / 서버가 준 거 -> 브라우저로 중계
    // (※ 3~4일차에 배울 스레드가 이 내부에서 양방향 블로킹을 풀기 위해 또 쓰임!)
    
    // -----------------------------------------------------------------
    // [나중에 채울 미래의 주차별 자리]
    // 5. 나중에 5~6주차 TLS MITM이 완성되면, 이 자리에 SSL_read/write가 들어옴 (STEP 4)
    // 6. 나중에 7~9주차 파일 탐지가 완성되면, 이 자리에 checkFileUpload()가 들어옴 (STEP 5)
    // -----------------------------------------------------------------

    closesocket(serverSock);
    closesocket(clientSock);
}

int main(int argc, char* argv[]) {
    // 인자 분기 (main.exe server)
    if (strcmp(argv[1], "server") == 0) {
        
        // =============================================================
        // [이번 주 스텝 1의 무대] : 서버 뼈대 구축 (수도코드 STEP 1)
        // =============================================================
        WSAStartup(...);
        SOCKET listenSock = socket(...);
        bind(listenSock, 18080);
        listen(listenSock, SOMAXCONN);

        // =============================================================
        // [이번 주 스텝 2의 무대] : 무한 루프와 멀티스레드 확장
        // =============================================================
        while(true) {
            SOCKET clientSock = accept(listenSock, NULL, NULL); // 브라우저 접속 수락
            if (clientSock != INVALID_SOCKET) {
                // 전화를 받자마자 전담 스레드를 파서 업무를 통째로 위임!
                // 메인 스레드는 곧바로 다음 전화를 받으러 accept로 올라감.
                std::thread t(HandleClient, clientSock);
                t.detach(); 
            }
        }
    }
    return 0;
}
