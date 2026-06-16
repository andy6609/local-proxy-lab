#include <stdio.h>
#include <string.h>  // 이건 strcmp 쓰려고
#include <WinSock2.h // 이건 소켓 함수들 쓰기 위해서 
#include <WS2tcpip.h> // 이건 inet_pton(IP주소 문자열 -> 숫자), getaddrinfo(도메인 이름-> IP숫자) 등 확장 TCP/IP 함수들 

#pragma comment(lib, "ws2_32.lib") // 동적 라이브러리 링크

void RunServer();
void RunClient();

int main(int argc, char* argv[]) { // 2번째 인자는: 문자열 배열이 시작 하는 주소를 넣는 거임
	if (arg < 2) {
		printf("사용법: server_proxy.exe [server or client]\n")
			return 1;
	}

	if (strcmp(arg[1], "server") == 0) { // 이렇게 strcmp 를 쓰는 이유는 C언어 에서는 == 연산자 자체가 메모리 주소를 보게끔 되어있어서 
		RunServer();
	}

	else if (strcmp(arg[1], "client") == 0) {
		RunClient();
	}
	else {
		printf("잘못된 인자임!.")
	}

}

/*
1.wsastartup 으로  window 라이브러리를 꺠워서 세팅 하고 2. 그다음에 듣기 전용 소켓 하나를 일단 만든다(대기큐는 이따 만드는거임. 이 소켓을 만든다고 해서 대기큐가 생기는게 아님) 3. 주소 구조체를 세팅해서 
(일단 내 컴퓨터 서버에 모든 데이터가 오게끔 하는거고) 그다음에 그 설정한 주소를 소켓에 바인드 시킨다(몇번이랑 몇번이라고 묶는거임 bind)? 그게 3번이고 그다음에 4번 스텝이 만들었던 listen socket 를 수신 대기 상태로 전환한다? (여기서 소켓을 대기큐로 만들어버림)
(여기서 궁금한점: 소켓을 만드는거랑 대기상태로 전환하는거랑 다른거가?) 그다음 스텝 5이 accept 를 하는소켓을 또 따로 만든다 (대기큐에서 꺼내서 실제 연결을 한다)
6. 버퍼를 만들어서 데이터를 읽는다 7. 자원반납후 쿨하게 종료
*/

void RunServer() {

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2.2), &wsaData) != 0 { // MAKEWORD와 &wsaData는 다 WSAStartup 에 넘어감. 2.2 버전 쓰고 이 메모리 주소에 넣으면 돼~ // Linux, mac 에서는 안해도 되는데(소켓이 내장되어있어서), window에서는 초기화 해줘야 함. 함수에게 2.2 버전을 쓴다고 알려주는거임 
		printf("WSAStartup failed: %d\n", WSAGetLastError());
		WSACleanup();
		return 1;

	}

	SOCEKT listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // 소켓을 하나 만들어서 listenSock에 넣는거임. AF_INET은 IPv4 주소 체계를 사용하겠다는 의미임. SOCK_STREAM은 TCP 소켓을 만들겠다는 의미임. IPPROTO_TCP는 TCP 프로토콜을 사용하겠다는 의미임. 이 함수가 성공하면 소켓 디스크립터를 반환하고, 실패하면 INVALID_SOCKET을 반환함.
	if(listenSock = = INVALID_SOCKET) {
		printf("socket failed: %d\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}
	
		
	struct sockaddr_in serverAddr; // sockaddr_in 구조체는 IPv4 주소를 표현하기 위한 구조체임. 이 구조체는 IP 주소와 포트 번호를 포함하고 있어서 서버가 어디에서 클라이언트의 연결을 기다릴지를 지정할 때 사용됨. family 는 주소체계, port 는 포트, addr 는 IP주소를 담는 필드임.
	memset(&serverAddr, 0, sizeof(serverAddr)); // memset은 메모리를 특정 값으로 초기화하는 함수임. 여기서는 serverAddr 구조체의 모든 바이트를 0으로 초기화하는데 사용됨. 이렇게 하면 구조체의 모든 필드가 0으로 설정되어서 나중에 필요한 필드만 값을 할당할 수 있게 됨.
	serverAddr.sin_family = AF_INET; // AF_INET는 IPv4 주소 체계를 사용하겠다는 의미임. 이 필드는 소켓이 사용할 주소 체계를 지정하는데 사용됨. sin 은 socket internet 
	serverAddr.sin_port = htons(18080); // htons는 호스트 바이트 순서를 네트워크 바이트 순서로 변환하는 함수임. 포트 번호는 16비트 정수로 표현되는데, 네트워크 통신에서는 바이트 순서가 다를 수 있기 때문에 이 함수를 사용해서 포트 번호를 올바르게 변환해야 함. 여기서는 18080 포트를 사용하겠다는 의미임. host to network short 
	serverAddr.sin_addr.s_addr = INADDR_ANY; // INADDR_ANY 는 서버가 모든 네트워크 인터페이스에서 들어오는 연결을 수락하도록 지정하는 상수임. 즉, 서버가 여러 개의 네트워크 인터페이스를 가지고 있을 때, 이 설정은 모든 인터페이스에서 클라이언트의 연결을 허용하겠다는 의미임. s_addr 는 IP주소를 담는 필드임.


	if (bind(listenSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR){ //  이 주소의 정보를 묶어줘 소켓에 sizeof 만큼. 왜 size 까지 알려주나. 타입을 캐스팅 하면 크기 정보가 사라져서 bind 입장에서는 주소가 있는건 알겠는데 이게 IPv4(16byte)인지 IPv6(28byte)인지 모르기 때문에 크기 정보도 같이 알려주는거임.
		closesocket(listenSock);
		WSACleanup();
		return 1;
	}
		
	if (listen(listenSock, SOAMXCONN) == SOCKET_ERROR) { // listen 함수는 소켓을 대기 상태로 만듦(대기큐). SOMAXCONN은 그냥 OS 가 정한 최댓값(최대 요청의 개수)으로 알아서 해라 
		closesocket(listenSock);
		WSACleanup();
		return 1;
	}

	printf(" 서버 18080 포트가 열렸음. 전화를 기다리겠음... (Blocking)\n");)

	SOCKET clientSock = accept(listenSok, NULL, NULL); // accept 함수는 대기 상태인 소켓에서 클라이언트의 연결 요청을 수락하는 함수임. 첫 번째 인자는 대기 상태인 소켓 디스크립터이고, 두 번째와 세 번째 인자는 클라이언트의 주소 정보를 저장할 버퍼와 그 크기를 나타내는 포인터임. 여기서는 클라이언트의 주소 정보가 필요 없으므로 NULL로 설정함. 이 함수가 성공하면 새로 생성된 소켓 디스크립터를 반환하고, 실패하면 INVALID_SOCKET을 반환함.
	if (clientSock == INVALID_SOCKET) {
		printf("accept failed: %d\n", WSAGetLastError());
		closesocket(listenSock);
		WSACleanup();
		return 1;
	}

	printf("브라우저 또는 클라이언트 연결 수락 성공!");

	// recv(): 들어온 데이터 읽기
	char buffer[4096]; // HTTP 데이터가 텍스트로 오기 때문에 버퍼는 문자 배열로 만들어야함. 
	memset(buffer, 0, sizeof(buffer)); // 버퍼 초기화
	int recvResult = recv(clientSock, buffer, sizeof(buffer) - 1, 0); // recv 함수는 소켓에서 데이터를 읽는 함수임.네 번째 인자는 플래그임. 여기서는 버퍼 크기보다 하나 작은 값을 전달해서 마지막 바이트를 null terminator로 남겨두는거임. 
	 
	if (recvResult > 0) {
		printf("\n[서버가 받은 데이터]\n%s\n", buffer);
	}
	else {
		printf("[서버] 데이터 수신 실패 또는 연결 종료: %d\n", WSAGetLastError());
	}

	closesocket(clientSock); // 소켓 닫기
	closesocket(listenSock); // 소켓 닫기
	WSACleanup(); // 윈속 라이브러리 정리
	printf("1회성 서버 접속 완료함. 프로그램 종료.");)

}
void RunClient()