/*
============================================================
 proxy_v1  —  M1: 양방향(full-duplex) 릴레이
============================================================
 execution-plan-to-mitm.md 의 M1 정의대로 '제품 수준'으로 새로 작성.
 (proxy_relay = 학습용 턴제. 여기는 그 확장이 아니라 처음부터 새로 짠 것.)

 M1 의 핵심 (M0 턴제와 뭐가 다른가):
   - 턴제(M0): 요청 받고 -> 서버에 보내고 -> 응답 받아서 -> 돌려줌  (한 번에 한 방향)
   - 양방향(M1): 클라->서버 / 서버->클라 '두 방향을 동시에' 흘려보냄.
                 한쪽이 끊기면 반대쪽도 깔끔히 정리.

 왜 양방향이 필요한가:
   - HTTP keep-alive: 한 연결로 요청/응답이 여러 번 왔다갔다 함.
   - 파일 업로드: 클라가 큰 데이터를 계속 올리는 동안 서버도 응답할 수 있음.
   - (나중에) HTTPS CONNECT 터널: 암호화 바이트가 양방향으로 끊임없이 흐름.
   => 한 방향씩 처리하면 위 상황에서 막히거나(블로킹) 데드락이 남.

 이 파일의 [직접] 부분 = relay() + 스레드2개 동시화 + 연결 생명주기(정리).
============================================================
*/

#include <stdio.h>
#include <string.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <thread>

#pragma comment(lib, "ws2_32.lib")

void RunServer();
void HandleClient(SOCKET clientSock);
SOCKET ConnectUpstream(const char* host, const char* port);
void Relay(SOCKET from, SOCKET to);
bool ParseHost(const char* request, char* outHost, int outHostSize);


int main() {
    RunServer();
    return 0;
}


// ============================================================
//  RunServer: 18080 포트로 듣고, 연결마다 스레드 하나씩 띄움
// ============================================================
void RunServer() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return;
    }

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(18080);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("bind failed: %d\n", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return;
    }

    if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
        printf("listen failed: %d\n", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return;
    }

    printf("[proxy_v1] 18080 listening... (full-duplex relay)\n");

    while (true) {
        SOCKET clientSock = accept(listenSock, NULL, NULL);
        if (clientSock == INVALID_SOCKET) {
            printf("accept failed: %d\n", WSAGetLastError());
            continue;   // 한 연결 실패해도 서버는 계속 돌아야 함
        }
        std::thread(HandleClient, clientSock).detach();
    }

    // (도달하지 않지만 형식상) 정리
    closesocket(listenSock);
    WSACleanup();
}


// ============================================================
//  HandleClient: 연결 하나를 끝까지 책임짐
//    1) 첫 요청 받아서 목적지(Host) 알아내고
//    2) 진짜 서버에 연결한 뒤
//    3) 양방향 릴레이를 '동시에' 돌림
// ============================================================
void HandleClient(SOCKET clientSock) {
    char buffer[16384];

    // --- 1. 첫 요청 받기 (목적지 Host 를 알아내기 위해 한 번 읽어야 함) ---
    int n = recv(clientSock, buffer, sizeof(buffer), 0);
    if (n <= 0) {
        closesocket(clientSock);
        return;
    }

    // --- 2. Host 파싱 (M1 단계라 단순 버전. M2 에서 견고하게 재구현 예정) ---
    char host[256];
    if (!ParseHost(buffer, host, sizeof(host))) {
        printf("[proxy_v1] Host 헤더 못 찾음. 종료\n");
        closesocket(clientSock);
        return;
    }
    printf("[proxy_v1] -> %s\n", host);

    // --- 3. 진짜 서버(upstream)에 연결 ---
    SOCKET upstream = ConnectUpstream(host, "80");
    if (upstream == INVALID_SOCKET) {
        printf("[proxy_v1] upstream 연결 실패: %s\n", host);
        closesocket(clientSock);
        return;
    }

    // --- 4. 이미 읽어둔 첫 요청을 upstream 에 먼저 보냄 ---
    //     (recv 로 한 번 꺼내버렸으니, 이건 릴레이 루프가 모르는 데이터.
    //      그래서 여기서 직접 한 번 흘려보내 주고, 그 다음부터 릴레이가 이어받음)
    {
        int sent = 0;
        while (sent < n) {
            int s = send(upstream, buffer + sent, n - sent, 0);
            if (s <= 0) break;
            sent += s;
        }
    }

    // --- 5. 양방향 릴레이를 '동시에' 실행 ---
    //   방향 A: client -> upstream  (별도 스레드)
    //   방향 B: upstream -> client  (지금 이 스레드)
    //   두 방향이 각자 자기 recv 에 매달려 있으므로 동시에 흐른다.
    std::thread up(Relay, clientSock, upstream);   // 방향 A
    Relay(upstream, clientSock);                    // 방향 B (현재 스레드가 직접)

    // 방향 B 가 끝났다는 건 upstream 이 더 보낼 게 없다는 뜻.
    // 방향 A 도 끝날 때까지 기다렸다가(join) 같이 정리해야 자원 누수가 없다.
    up.join();

    // --- 6. 양쪽 소켓 정리 ---
    closesocket(upstream);
    closesocket(clientSock);
    printf("[proxy_v1] %s done.\n", host);
}


// ============================================================
//  Relay: from 에서 읽어서 to 로 그대로 흘려보냄 (한 방향)
//    - recv 가 0 이하가 되면(상대가 끊거나 에러) 루프 종료
//    - 종료 시 to 쪽에 shutdown(SD_SEND) 로 "나 이제 안 보낸다"는 FIN 을 보냄
//      -> 반대 방향 릴레이의 recv 도 곧 0 을 받고 끝나게 됨 (한쪽 끊기면 양쪽 정리)
// ============================================================
void Relay(SOCKET from, SOCKET to) {
    char buf[16384];
    int n;
    while ((n = recv(from, buf, sizeof(buf), 0)) > 0) {
        // send 는 한 번에 n 바이트를 다 못 보낼 수 있음 -> 다 보낼 때까지 반복 (부분 전송 대비)
        int sent = 0;
        while (sent < n) {
            int s = send(to, buf + sent, n - sent, 0);
            if (s <= 0) { sent = -1; break; }   // 보내기 실패 -> 더 못 감
            sent += s;
        }
        if (sent < 0) break;
    }

    // from 이 끝났음을 to 에게 알림 (half-close).
    // 이게 있어야 반대 방향이 무한 대기(블로킹)에 빠지지 않고 같이 종료된다.
    shutdown(to, SD_SEND);
}


// ============================================================
//  ConnectUpstream: 도메인 -> IP 변환 후 연결, 성공 시 소켓 반환
//    실패하면 INVALID_SOCKET 반환 (호출 쪽이 확인)
// ============================================================
SOCKET ConnectUpstream(const char* host, const char* port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* info = NULL;
    if (getaddrinfo(host, port, &hints, &info) != 0) {
        return INVALID_SOCKET;
    }

    SOCKET sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(info);
        return INVALID_SOCKET;
    }

    if (connect(sock, info->ai_addr, (int)info->ai_addrlen) == SOCKET_ERROR) {
        closesocket(sock);
        freeaddrinfo(info);
        return INVALID_SOCKET;
    }

    freeaddrinfo(info);   // 다 썼으니 반납 (누수 방지)
    return sock;
}


// ============================================================
//  ParseHost: 요청에서 "Host:" 값(목적지 호스트명) 추출
//    [M1 단계 한정 단순 버전] M2 에서 부분수신/헤더경계/방어까지 견고화 예정.
// ============================================================
bool ParseHost(const char* request, char* outHost, int outHostSize) {
    const char* p = strstr(request, "Host:");
    if (p == NULL) return false;

    p += 5;
    while (*p == ' ') p++;

    int i = 0;
    while (*p != '\r' && *p != '\n' && *p != ':' && *p != '\0' && i < outHostSize - 1) {
        outHost[i] = *p;
        i++;
        p++;
    }
    outHost[i] = '\0';
    return true;
}
