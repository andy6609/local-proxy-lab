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
    WSACleanup          8. 정리 
                                                                           
                                                                           */