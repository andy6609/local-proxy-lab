#include <stdio.h>
#include <string.h>  // 이건 strcmp 쓰려고
#include <WinSock2.h> // 이건 소켓 함수들 쓰기 위해서
#include <WS2tcpip.h> // 이건 inet_pton(IP주소 문자열 -> 숫자), getaddrinfo(도메인 이름-> IP숫자) 등 확장 TCP/IP 함수들
#include <thread> // 멀티스레딩을 위해서, 실제 프록시는 여러 브라우저가 요청을 하는걸 받아야함 (당연)

#pragma comment(lib, "ws2_32.lib") // 동적 라이브러리 링크

/*
단일 통신과 이 멀티스레드 환경의 함수 차이 도약표 

void RunServer() {
    WSAStartup 
    Socket -> listenSock
    bind
    listen                              => 계속 연결 받음 

    accept -> clientSock 생성 (새 소켓)   => accept 가 만들어준 소켓으로 실제 데이터 통신 
    recv(clientSock) -> buffer
    closesocket(clientSock)
    closesocket(listenSock)
    WSACleanup
*/

/*
void RunServer() {
    WSAStartup
    Socket -> listenSock
    bind
    listen                      // 얘는 왜 스레드로 안만들어도 되냐면, 클라이언트는 그냥 서버에 연결해서 데이터 보내고 끝나는거라서, 굳이 멀티스레드로 만들 필요가 없음.

    while (true) {             // 브라우저는 html도 보내고~ css도 보내고~ 이미지도 보내고~ 하기 때문에 계속 들어오는 연결을 다 받기 위해서 무한 루프로 받음 
        accept -> clientSock 생성           // 어 얘가 메인 스레드임. 이 밑에 줄에 있는 애가 추가 스레드 // 스레드 개념 잊었을까봐 다시 정리: 쉽게 말해서 코드를 위에서 아래로 실행하는 하나의 흐름 + 스레드당 1MB+ 만개 만들면 좀 느려짐 (Go 루틴은 100만개도 가능 2kb여서)
        std::thread t(HandleClient, clientSock); // 클라이언트 소켓을 인자로 해서 스레드 하나 만들어서 그 스레드에서 클라이언트 처리하게 함.
        t.detach(); // 스레드 분리, 이렇게 하면 메인 스레드가 클라이언트 처리하는 스레드가 끝날 때까지 기다리지 않고 바로 다음 클라이언트 연결을 받을 수 있음.
}

void HandleClient(Socket clientSock){        // 이러면 연결 하나당 스레드를 만들고, 그 연결 끝나면 스레드도 사라짐. thread-per-connection~~
    recv(clientSock) -> buffer                  // 이게 이점이 메인 스레드가 이걸 다하면 다 blokcing 됨 obviously
    closesocket(clientSock)
}

=> 여기서 알아야 할게 bind + listen + accept + recv 만으로 브라우저 요청이 오는거는
bind 로 18080 포트를 '선점' 했기 떄문이다
그래서 누구든 127.0.0.1:18080 으로 보낸 건 전부 OS가 나한테 전달해줌.
브라우저 정보가 막 오는거는 브라우저가 그 주소를 보냈으니까 오는 거임.

참고로 127.0.0.1 는 IP 맞는데, "내 컴퓨터 자신"을 가리키는 특별 local host IP임
*/


void RunServer();
void RunClient();
void HandleClient(SOCKET clientSock); // 클라이언트 처리하는 함수, 이걸 스레드에서 실행할거임

int main(int argc, char* argv[]) { // 2번째 인자는: 문자열 배열이 시작 하는 주소를 넣는 거임
    if (argc < 2) {
        printf("사용법: server_proxy.exe [server or client]\n");
        return 1; // main은 int 함수라 값을 돌려줘야 함 (void가 아님!). 비정상 종료
    }

    if (strcmp(argv[1], "server") == 0) { // 이렇게 strcmp 를 쓰는 이유는 C언어 에서는 문자열(char*)에 == 를 쓰면 내용이 아니라 메모리주소를 비교해서, 내용을 비교하려면 strcmp를 써야함. 이거는 두 문자열을 비교하는 함수임
        RunServer();
    }

    else if (strcmp(argv[1], "client") == 0) {
        RunClient();
    }
    else {
        printf("잘못된 인자임!.");
    }

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
        SOCKET clientSock = accept(listenSock, NULL, NULL); // accept 함수는 대기 상태인 소켓에서 클라이언트의 연결 요청을 수락하는 함수임. 첫 번째 인자는 대기 상태인 소켓 디스크립터이고, 두 번째와 세 번째 인자는 클라이언트의 주소 정보를 저장할 버퍼와 그 크기를 나타내는 포인터임. accept 에 대해서 오해를 풀자면 얘는 두가지 일을 동시에 함. 1. 어 대기큐에서 꺼내서 실제 연결을 한다. 2. 그 연결을 위한 소켓을 새로 만들어서 반환한다. (이때 반환되는 소켓은 listenSock과는 다른 소켓임. listenSock은 계속 대기 상태로 남아있고, clientSock은 실제 연결된 소켓임.) 그래서 socket() 함수는 한번 쓰였는데 소켓은 2개임.
    
        std::thread mythread (HandleClient, clientSock);// 새 스레드를 만들어서, 거기서 HandleClient 함수를 실행해주셈 
        // 클래스를 만든거기 때문에 객체를 만들때 생성자 함수를 넘겨야겠지? 넘길려면 인자를 넘겨야 겠지?
        mythread.detach(); // join() 이 아니라 detach()를 쓰는 이유는, join을 쓰면 메인 스레드가 이 mythread 스레드가 끝날 때까지 기다려야 하는데, 그러면 메인 스레드가 accept()를 못하고 블로킹 되서 다음 클라이언트 연결을 못 받음. 그래서 detach()를 쓰는거임. detach()를 쓰면 mythread 스레드가 끝나든 말든(알아서 일 끝내고 사라져라) 메인 스레드는 바로 다음 accept()로 넘어감.
    }

    // 이거는 이제 while문 안에서 스레드로 만들어서 처리하기 때문에, 메인 스레드는 계속 accept 하면서 연결 받고, 클라이언트 처리하는 스레드는 HandleClient 함수에서 처리하게 됨. 그래서 이 아래 코드는 이제 필요가 없음.

}


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

void RunClient() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) { // 주소를 넘겨주면 Startup 함수가 이 구조체에 라이브러리 정보 넣어줌~
        printf("WSAStartup failed: %d\n", WSAGetLastError()); // 초기화 실패하면 에러 출력하고
        return; // 더 진행 못하니 종료 (void 함수라 값 없는 return;)
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // 클라이언트도 소켓 하나 만듦. 세번째 인자 0으로 해도 되는데 TCP 명시적으로 씀.
    if (sock == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }

    struct sockaddr_in serverAddr; // 어디로 연결할지 '목적지' 주소 (서버는 INADDR_ANY였지만 클라는 콕 집어줘야 함)
    memset(&serverAddr, 0, sizeof(serverAddr)); // 초기화
    serverAddr.sin_family = AF_INET; // IPv4
    serverAddr.sin_port = htons(18080); // 내가 띄운 서버랑 같은 포트로 맞춰야 연결됨. 내 컴퓨터 방식(내가 보는 숫자) 18080을 네트워크 방식 18080으로 바이트 순서 뒤집어줌.
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr); // IP 문자열 "127.0.0.1" -> 숫자(바이너리)로 변환해서 넣어줌.  presentation (사람이 보는 문자열을 -> 네트워크가 보는 문자열(4바이트로))

    printf("[클라이언트] 127.0.0.1:18080 로 연결 시도...\n");
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) { // 서버에 실제로 연결 거는 단계, 이걸로 TCP 3 way handshake)
        printf("connect failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return;
    }

    const char* request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"; // 서버에 보낼 HTTP 요청 (C++이라 const char* 로)/ 네크워크에서 주고 받는건 byte 덩어리임. "문자열" 이 아님. 그래서 char buffer[] 는 문자배열 보다는 "바이트를 담을 그릇" char 하나에 1byte 이기 때문(바이트를 담는 표준 그릇). HTTP 는 "문자열 처럼" 보이나. HTTP 헤더는 사람이 보기 쉽게 나와있어서 그럼 GET/HTTP/1.1 이런거 처럼/. 근데 이거는 헤더라 이렇게 보이는거고 본문은 이미지 동영상 같은 "바이너리 일수도 있음" 이 클라이언트에서 const char* 로 만든거는 이미 있는 문자열을 가리키기만 하면 되는거라서 새로 그릇을 만들 필요 없이 있는걸 가리켜서 send에 넘기는 거임.
    send(sock, request, (int)strlen(request), 0); // 위 요청을 서버로 전송
    printf("[클라이언트] 데이터 발송 완료!\n");

    closesocket(sock); // 소켓 닫기
    WSACleanup(); // 윈속 정리
}