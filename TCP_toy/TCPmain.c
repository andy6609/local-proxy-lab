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
    WSAStartup()        1. Winsock 초기화
    socket()            2. 소켓 생성
    connect()           3. naver.com:80 연결
    send()              4. HTTP 요청 전송
    recv()              5. 응답 받기
    printf()            6. 화면에 출력
    closesocket()       7. 소켓 닫기
    WSACleanup          8. 정리     */

#include <stdio.h>  
#include <WinSock2.h> // socket funciton 들 쓰려고 // 텍스트 헤더파일 가져오기 compiler 에게 "WSAStartup이 어케 생겼는지 알려주는거고 
#pragma comment(lib, "ws2_32.lib")  
    // ws2_32.dll 연결 해줘 + pragma 는 컴파일러에게 특별 지시. 여기선 "ws2_32.lib 링크 해줘 의미임. Go 언어 에서는 import 로 자동 링크 
    // 이름이 comment 인 이유는 링커에게 말 그대로 comment 남기기 이고, 컴파일러에게 부탁하는거니까 컴파일러가 빌드할 때 파일 안에 메모를 남기는거임
    // lib 연결 해달라고 
    // include 는 텍스트 파일을 가져오는건데 -> .h 파일은 텍스트(사람이 읽을 수 있음)
    //                                       -> .lib 파일은 바이너리 파일이여서 include 안됨. 부품임 link(연결) 해야 하는 부품.


int main() {
    WSADATA wsaData;                                        // winsock 시스템 정보 담는 구조체
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);      // winsock 2.2 버전으로 initialize. 그리고 & 여기에 주소 전달
                                                            // wsaData 안에 저장되는 것들 -> winsock 버전 정보, 시스템이 지원하는 최대 소켓 수 등 
                                                            // MAKEWORD 는 winsock 최신 버전 써달라는 매크로 함수임 
    if (result != 0) {
        printf("WSAStartup 실패: %d\n", result);
        return 1;
    }
    printf("Winsock 초기화 성공!\n");

    WSACleanup();
    return 0;
}                                                       /*
                                                         이 코드가 하는 일 : windows 한테 나 소켓 쓸거니까 준비해줘
                                                         성공하면 초기화 성공이고 실패하면 에러 출력       
                                                        */
                                                         