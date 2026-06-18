#include <stdio.h>
#include <string.h>  // 이건 strcmp 쓰려고
#include <WinSock2.h> // 이건 소켓 함수들 쓰기 위해서
#include <WS2tcpip.h> // 이건 inet_pton(IP주소 문자열 -> 숫자), getaddrinfo(도메인 이름-> IP숫자) 등 확장 TCP/IP 함수들
#include <thread> // 멀티스레딩을 위해서, 실제 프록시는 여러 브라우저가 요청을 하는걸 받아야함 (당연)

#pragma comment(lib, "ws2_32.lib") // 동적 라이브러리 링크

/*
바꿔야 할것
HandleClient 함수 바꾸기 - 메인 작업임
지금은 받아서 printf 로 출력하고 끝나는데
이제 앞으로는 받아서 -> Host 파싱 -> 진짜 서버 connect -> 요청 넘기고 -> 그걸 응답을 또 받아서 브라우저에게 넘길거임

HandleClient 가 쓸 도우미 함수 2개를 또 만들어야해. 그건 또 뭘까
Host 를 뽑는 함수 (paseHost)
도메인을 IP 로 바꿔주는 함수(getaddrinfo)

그리고 여기서는  Runclient 는 안씀
이제 리얼 scenario 로 가기 때문에
크롬 브라우저 -> 내 프록시(RunServer) -> 진짜 서버(httpbin.org)
이제 이 프록시 파일은 서버 이자 클라이언트 역할을 한다~
*/


void RunServer();
void HandleClient(SOCKET clientSock); // 클라이언트 처리하는 함수, 이걸 스레드에서 실행할거임

int main() { // 프록시는 서버(프록시) 하나만 돌리니까 server/client 분기가 필요 없음 -> 인자도 안 받음
    RunServer(); // 바로 프록시 서버 실행
    return 0; // 정상 종료
}

void RunServer() {
    WSADATA wsaData;  // 그래서 이거 만들어서 어따쓰냐? 그냥 WSAStartup 할 때 이거의 주소를 넘겨주면, WSAStartup이 이 구조체에 윈속 라이브러리의 상태 정보를 채워넣어줌. 나중에 WSAGetLastError 같은 함수로 에러 정보를 얻을 때도 이 구조체의 정보가 필요할 수 있음. 그래서 일단 만들어서 초기화 해주는거임.
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0 ) { // MAKEWORD와 &wsaData는 다 WSAStartup 에 넘어감. 2.2 버전 쓰고 이 메모리 주소에 넣으면 돼~ // Linux, mac 에서는 안해도 되는데(소켓이 내장되어있어서), window에서는 초기화 해줘야 함. 함수에게 2.2 버전을 쓴다고 알려주는거임 
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        WSACleanup();
        return;

    }

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // 소켓을 하나 만들어서 listenSock에 넣는거임. 이따가 주소 구조체에서 타입 캐스팅 할건데 왜 이렇게 쓰나 : 소켓 자체는 범용으로 만들 수 있지만, OS가 어떻게 동작해야 할지는 알아야 한다. 그리고 범용타입 sockaddr에는 IP주소를 못 담기도 함.
    if(listenSock == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }

    struct sockaddr_in serverAddr; // 서버를 찾아올 주소 정해주기
    memset(&serverAddr, 0, sizeof(serverAddr)); // 초기화
    serverAddr.sin_family = AF_INET; // IPv4
    serverAddr.sin_port = htons(18080); // 포트 번호
    serverAddr.sin_addr.s_addr = INADDR_ANY; // 서버가 모든 네트워크 인터페이스에서 들어오는 연결을 수락하도록 지정

    if(bind(listenSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) { // bind 함로 그 struct 주소를 소켓에 묶는 거임. 캐스팅 할때 왜 메모리 주소를 주고 받냐 -> bind 는 구조체를 다 통쨰로 받지 않고 메모리 주소로 받음. 캐스팅도 포인터 타입을 하는 이유가 *그 주소를 어떤 타입으로 볼지* 하는거임 (이 주소를 이 타입으로 봐달라~)
        printf("bind failed: %d\n", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return;
    }

    if(listen(listenSock, SOMAXCONN) == SOCKET_ERROR) { // listen 함수는 소켓을 대기 상태로 만듦(대기큐). SOMAXCONN은 최댓값이고. listen 함수는 소켓을 대기 상태로 만드는건데 궁금하면 F12눌러서 보셈 근데 시그니첨나 있고 자세한건 ws2_32.dll 안에 바이너리로 되어있어서 못 봄. 근데 설명을 좀 적어보자면, ㄹㅇ os 커널한테 대기 모드로 바꿔달라고 요청하는거 맞고, os가 그 소켓에 대해"연결대기 요청 큐"를 메모리에 올려둠. 큐 크기는 backlog 라고 함. 여튼 이후 들어오는 SYN 패킷들이 이 큐에 쌓임.
        closesocket(listenSock);
        WSACleanup();
        return;
    }

    printf("서버 18080 포트가 열렸음. 전화를 기다리겠음... (Blocking)\n");

    while (true) {
        SOCKET clientSock = accept(listenSock, NULL, NULL); // accept 함수는 대기 상태인 소켓에서 클라이언트의 연결 요청을 수락하는 함수임. 첫 번째 인자는 대기 상태인 소켓 디스크립터이고, 두 번째와 세 번째 인자는 클라이언트의 주소 정보를 저장할 버퍼와 그 크기를 나타내는 포인터임. accept 에 대해서 오해를 풀자면 얘는 두가지 일을 동시에 함. 1. 어 대기큐에서 꺼내서 실제 연결을 한다. 2. 그 연결을 위한 소켓을 새로 만들어서 반환한다. (이때 반환되는 소켓은 listenSock과는 다른 소켓임. listenSock은 계속 대기 상태로 남아있고, clientSock은 실제 연결된 소켓임.) 그래서 socket() 함수는 한번 쓰였는데 소켓은 2개임. accept 가 먼저 실행돼서 소켓을 만들어 돌려주고, 그 결과를 clientsock 에 저장 하는거임. accept 함수는 "성공하면 새 소켓을 반환한다" 라고 설계된 함수임.
    
        std::thread mythread (HandleClient, clientSock);// 새 스레드를 만들어서, 거기서 HandleClient 함수를 실행해주셈 
        // 클래스를 만든거기 때문에 객체를 만들때 생성자 함수를 넘겨야겠지? 넘길려면 인자를 넘겨야 겠지?
        mythread.detach(); // join() 이 아니라 detach()를 쓰는 이유는, join을 쓰면 메인 스레드가 이 mythread 스레드가 끝날 때까지 기다려야 하는데, 그러면 메인 스레드가 accept()를 못하고 블로킹 되서 다음 클라이언트 연결을 못 받음. 그래서 detach()를 쓰는거임. detach()를 쓰면 mythread 스레드가 끝나든 말든(알아서 일 끝내고 사라져라) 메인 스레드는 바로 다음 accept()로 넘어감.
    }

    // 이거는 이제 while문 안에서 스레드로 만들어서 처리하기 때문에, 메인 스레드는 계속 accept 하면서 연결 받고, 클라이언트 처리하는 스레드는 HandleClient 함수에서 처리하게 됨. 그래서 이 아래 코드는 이제 필요가 없음.

}


// [도우미 함수] 받은 요청에서 "Host:" 줄의 값(목적지 호스트명)을 뽑아 outHost 에 복사한다.
//   예) 요청 안에 "Host: httpbin.org\r\n" 이 있으면 -> outHost = "httpbin.org"
//   성공하면 true, Host 헤더를 못 찾으면 false.
bool parseHost(const char* request, char* outHost, int outHostSize) {
    // 1. 요청 문자열(request) 안에서 "Host:" 가 시작하는 위치를 찾는다.
    //    strstr = 큰 문자열 안에서 특정 단어가 어디 있는지 찾아 그 위치(포인터)를 돌려줌. 없으면 NULL.
    const char* p = strstr(request, "Host:");
    if (p == NULL) return false; // Host 헤더가 없으면 실패

    p += 5;                // "Host:" 5글자만큼 포인터를 앞으로 밀어 -> 값 바로 앞으로 이동
    while (*p == ' ') p++; // "Host: httpbin.org" 처럼 콜론 뒤 공백이 있으면 건너뜀

    // 2. 값의 끝(\r, \n, ':', 또는 문자열 끝)이 나올 때까지 한 글자씩 복사
    //    ':' 에서 멈추는 이유: "Host: httpbin.org:8080" 처럼 포트가 붙어있으면 호스트명만 뽑으려고
    int i = 0;
    while (*p != '\r' && *p != '\n' && *p != ':' && *p != '\0' && i < outHostSize - 1) {
        outHost[i] = *p;
        i++;
        p++;
    }
    outHost[i] = '\0'; // 뽑은 문자열 끝에 널문자 붙이기 (그래야 %s 등에서 안전)
    return true;
}


/*
 
*/

void HandleClient(SOCKET clientSock) {
    char buffer[8192]; // 8192 바이트 공간 확보 
    memset(buffer, 0, sizeof(buffer));

    // 1. 브라우저가 보낸 요청 받기
    int n = recv(clientSock, buffer, sizeof(buffer) - 1, 0); // n으로 받는 이유가 딱 받은 만큼만 전달해야 해서 // buffer 에는 "GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n..." 예시로 이런식으로 담김. n 에는 그러면 53이 저장됨. recv가 원래 그런애임, 몇바이트 채웠는지 숫자로 돌려줌 
    if (n <= 0) { // 못 받았거나(0) 에러(-1)면 그냥 정리하고 끝
        closesocket(clientSock);
        return;
    }
    printf("\n[프록시] 브라우저 요청 받음 (%d bytes)\n", n);

    // 2. 요청에서 목적지 호스트(Host:) 뽑기
    char host[256]; // 목적지 호스트명을 담을 버퍼임(도메인 명은 최대 255자라서) 빈그릇 준비~
    if (!parseHost(buffer, host, sizeof(host))) { // parseHost가 false 면 뭐 종료
        printf("[프록시] Host 헤더를 못 찾음. 종료\n");
        closesocket(clientSock);
        return;
    }
    printf("[프록시] 목적지 호스트: %s\n", host);

    // 3. 도메인 이름 -> IP 변환 (DNS 조회)
    //    "httpbin.org" 같은 문자열은 connect 에 바로 못 씀 -> 숫자 주소로 바꿔야 함.
    //    getaddrinfo 는 hints(원하는 조건)를 받아 결과를 serverInfo 에 채워줌.
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP

    struct addrinfo* serverInfo = NULL;
    if (getaddrinfo(host, "80", &hints, &serverInfo) != 0) { // "80" = http 기본 포트
        printf("[프록시] DNS 조회 실패: %s\n", host);
        closesocket(clientSock);
        return;
    }

    // 4. 진짜 서버로 가는 '새 소켓'(upstream) 만들고 연결
    //    -> 여기서부터 프록시가 '클라이언트' 역할을 함 (진짜 서버한테 전화 거는 쪽)
    SOCKET upstream = socket(serverInfo->ai_family, serverInfo->ai_socktype, serverInfo->ai_protocol);
    if (upstream == INVALID_SOCKET ||
        connect(upstream, serverInfo->ai_addr, (int)serverInfo->ai_addrlen) == SOCKET_ERROR) {
        printf("[프록시] 진짜 서버 연결 실패\n");
        freeaddrinfo(serverInfo); // getaddrinfo 가 잡아준 메모리 반납
        closesocket(clientSock);
        return;
    }
    freeaddrinfo(serverInfo); // 주소 정보 다 썼으니 반납
    printf("[프록시] %s 연결 성공! 요청 전달...\n", host);

    // 5. 브라우저가 보낸 요청을 그대로 진짜 서버에 전달
    send(upstream, buffer, n, 0); // ★ n 바이트(받은 만큼) 그대로! strlen 금지

    // 6. 진짜 서버의 응답을 받아서 브라우저로 되돌려줌 (릴레이 루프)
    //    응답이 끝날 때(recv 가 0 이하)까지 계속 받아서 그대로 넘김
    int m;
    while ((m = recv(upstream, buffer, sizeof(buffer), 0)) > 0) {
        send(clientSock, buffer, m, 0); // ★ 받은 m 바이트만큼 그대로 (응답은 바이너리라 %s/strlen 금지)
    }

    // 7. 양쪽 소켓 다 닫기 (clientSock = 브라우저, upstream = 진짜 서버)
    closesocket(upstream);
    closesocket(clientSock);
    printf("[프록시] %s 중계 완료. 연결 닫음\n", host);
}

/*
  [기록용] step2 버전 HandleClient: 받아서 printf 로 출력만 하고 끝 (릴레이 X)
  void HandleClient(SOCKET clientSock) {
    char buffer[4096]; // HTTP 데이터가 텍스트로 오기 때문에 버퍼는 문자 배열로 만들어야함.
    memset(buffer, 0, sizeof(buffer)); // 버퍼 초기화
    int recvResult = recv(clientSock, buffer, sizeof(buffer) - 1, 0); // recv 함수는 소켓에서 데이터를 읽는 함수임. 네 번째 인자는 플래그임. 여기서는 버퍼 크기보다 하나 작은 값을 전달해서 마지막 바이트를 null terminator로 남겨두는거임.

    if (recvResult > 0) {
        printf("\n[서버가 받은 데이터]\n%s\n", buffer);
    }
    else {
        printf("[서버] 데이터 수신 실패 또는 연결 종료: %d\n", WSAGetLastError());
    }

    closesocket(clientSock); // 소켓 닫기
  }
*/