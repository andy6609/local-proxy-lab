// naver.com:80 에 TCP 연결해서 
// HTTP 요청 보내고
// 응답 받아서 출력 하는게 이 프로젝트 의 목표임 
/* 구조는 
                  우리 프로그램                              네이버 서버
                                   -> TCP 연결 (connect) ->
                                   -> HTTP 요청 (send)   ->
                                   "GET/ HTTP/1.0/r/n/r/n" 
                                                           <- HTTP 응답 (recv)
                                                            " HTTP/1.1/ 200 OK
                                                                Content-Type : text/html
                                                                ...
                                                                <html>..."
                                    -> printf로 화면에 출력 

    출력은 터미널에 텍스트로 HTTP/1.1 200 ok 뭐 ~~ 이런식으로 나옴 <html> < head>
                                                                           
                                                                           
[전체 코드의 흐름은]
1. WSAStartup()     → Winsock 초기화               window 에게 알리지 않으면 socket 생성해도 에러남  
2. socket()         → 소켓 생성                    실제 통신할 "전화기"를 만드는 것 
3. sockaddr_in 설정 → 서버 주소 설정               "어디로 연결할지" 목적지 정보 설정 하는 것. IP + 포트 조합
4. connect()        → naver.com:80 연결            TCP로 핸드셰이크 시작. 실제로 네이버 서버랑 연결 수립
5. send()           → HTTP 요청 전송               GET 같이 페이지 요청 
6. recv()           → 응답 받기                    네이버 서버가 보낸 HTML 데이터 받기
7. printf()         → 화면에 출력                  recv로 받은 데이터 콘솔에 출력
8. closesocket()    → 소켓 닫기                    통신 끝났으니 소켓 반납 
9. WSACleanup()     → 정리                         WSAStartup 했으니 Winsock 리소스 반닙
 */

#include <stdio.h>  
#include <WinSock2.h> // socket funciton 들 쓰려고 // 텍스트 헤더파일 가져오기 compiler 에게 "WSAStartup이 어케 생겼는지 알려주는거고 
#pragma comment(lib, "ws2_32.lib")  
    // ws2_32.dll 연결 해줘 + pragma 는 컴파일러에게 특별 지시. 여기선 "ws2_32.lib 링크 해줘 의미임. Go 언어 에서는 import 로 자동 링크 
    // 이름이 comment 인 이유는 링커에게 말 그대로 comment 남기기 이고, 컴파일러에게 부탁하는거니까 컴파일러가 빌드할 때 파일 안에 메모를 남기는거임
    // lib 연결 해달라고 
    // include 는 텍스트 파일을 가져오는건데 -> .h 파일은 텍스트(사람이 읽을 수 있음)
    //                                       -> .lib 파일은 바이너리 파일이여서 include 안됨. 부품임 link(연결) 해야 하는 부품.


int main() {                                                // WSAStartup = WSA (Windows Sockets API) + Startup(시작/초기화)
    // 이 초기화를 하면 (WSAStartup을 호출하면 ws2_32.dll 내부 준비하고, 소켓을 쓸 준비함
    // wsaData에 시스템 정보를 채워줌 
    WSADATA wsaData;                                        // winsock 시스템 정보 담는 구조체
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);      // winsock 2.2 버전으로 initialize. 그리고 & 여기에 주소 전달
    // wsaData 안에 저장되는 것들 -> winsock 버전 정보, 시스템이 지원하는 최대 소켓 수 등 
    // MAKEWORD 는 winsock 최신 버전 써달라는 매크로 함수임 
    if (result != 0) {
        printf("WSAStartup 실패: %d\n", result);
        return 1;
    }
    printf("Winsock 초기화 성공!\n");                        /*
                                                         이 코드가 하는 일 : windows 한테 나 소켓 쓸거니까 준비해줘(by WSAStartup- W api 함수 호출하며)
                                                         성공하면 초기화 성공이고 실패하면 에러 출력
                                                        */
 // STEP 2 : 소켓 생성 
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);     // socket() 함수는 파라미터가 3개인데, AF는 Address family (주소 체계)이고 INET은 internet
                                                       // 그래서 AF_INET은 IPv4 주소 체계이고 (AF_INET6는 IPv6), SOCK_STREAM은 스트림 방식을 TCP 를 쓴다는것임. SOCK_DGRAM은 UDP, 마지막 인자 0 은 프로토콜 번호임 
    if (sock == INVALID_SOCKET) {           // 그냥 nil 같은 거임 
        printf("소켓 생성 실패: %d\n", WSAGetLastError());  // GO에서는 err.Error()로 바로 에러 메세지 나오지만, C에서는 숫자로 나오고 GetLastError 를 써야함 
        WSACleanup();
        return 1;
    }
    printf("소켓 생성 성공! ");

  // STEP 3:서버 주소 설정
    struct sockaddr_in serverAddr;                  // 인터넷 주소 정보 담는 구조체 선언
    /*
     이 구조체 안에 있는것들
     serverAddr
    ├── sin_family   → 주소 체계
    ├── sin_port     → 포트 번호
    └── sin_addr     → IP 주소 ← 여기!
          └── s_addr → 실제 IP 숫자
    */
    memset(&serverAddr, 0, sizeof(serverAddr));     // 메모리를 특정 값으로 채우는 C언어 함수인데(winsock2.h 가 string.h를 포함하고 있어서)  , serverAddr 변수 메모리 주소를 0 으로 해라. 안하면 쓰레기 값 채워지니까. 3번째 인자에 sizeof 를 쓰는건  이거 대신에 999 이렇게 넣으면 serverAddr 를 넘어서 다른 값까지 0으로 덮어씌워버릴 수도 있음.
    serverAddr.sin_family = AF_INET;                // sin_family는 우리가 sockaddr_n 구조체로 만들어졌으니까 그 안에 있는 멤버 변수이구요. sin 은 socket internet 그리고 family 는 주소 체계 종류 임"어떤 주소 체계 쓸지.
    /*/ go 언어에서는 net.Dial("tcp", "223.130.200.104:80")
//                                        ↑
//                        IPv4 주소 형식이면 자동으로 AF_INET
//                        Go가 내부적으로 sin_family 설정해줌*/
    serverAddr.sin_port = htons(80);            // 구조체안에서 포트 번호를 저장하는 멤버임. htons 는 windowapi 함수(h = host, to = 변환, n = 네트워크, s = short) 
    inet_pton(AF_INET, "223.130.192.247", &serverAddr.sin_addr);
    /* ient_pton 에 대해서 알아보자..... -> 일단 Winsock API 함수임!!! 
    
    "internet , presentation, to , network 인데" 사람이 있는 ip 문자열을 컴터가 읽는 숫자로 변환하기야. 사람이 읽는 ip 는 숫자이고 컴터가 읽는 ip 는 0xDF82COF7 이런 느낌인데, 16진수니까 메모리에 4바이트로 저장됨. 네트워in크로 전송할때는 문자열 말고 숫자형식이 필요함

    int inet_pton(int af, const char*src, void*dst);
                  주소 체계, 입력(문자열 IP), 출력(숫자IP 저장할 곳)

     serverAddr.sin_addr.s_addr = inet_pton(""); <- 전에 이렇게 적었었는데 잘못된 코드 였음. 
    */
    

  // STEP 4 : 연결하기(TCP 만)  "Unlike Go , C 는 socket() 따로 connect() 따로 
   int connectResult = connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)); // connect () 반환값을 받을 변수, 성공하면 0 실패 하면 socket error // connect () 함수는 실제 TCP 연결 시작하는 함수 -> 이거 하면 3way handshake 
                                                                                         // 이 함수의 인자값 -> (우리가 만든 소켓, 서버 주소 정보<sockaddr 타입으로 변환>, 구조체 크기) connect(SOCKET, const struct sockaddr*, int) 
                                                                                                                // 위에서 형 변환 하는 이유가 우리가 만든건 sockaddr_in 타입인데 sockaddr* 로 바꾼게 sockaddr_in <IPv4 전용 구조체>, IP 포트 설정 편함.
                                                                                                                // 근데 이걸 먼저 써서 sin_port 나 sin_addr 를 받고 sockaddr* 로 변환해서 IPv4 이던 IPv6이던 받게함.
    if (connectResult == SOCKET_ERROR) {
        printf("연결 실패: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    printf("네이버 연결 성공!\n"); // 네이버랑 연결은 됐는데 아직 아무 말도 안한 상태

   // STEP 5

    char* request = "GET / HTTP/1.0\r\nHost: naver.com\r\n\r\n";  // 특별한 바이너리가 아니라 진짜 텍스트 규칙대로
    int sendResult = send(sock, request, strlen(request), 0);  // 이 문자열을 (TCP에 연결된)소켓으로 전송
    if (sendResult == SOCKET_ERROR) {
        printf("전송 실패: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    printf("HTTP 요청 전송 성공!\n");
}




                                              