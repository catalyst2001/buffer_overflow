#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <WinSock2.h>

#pragma comment(lib, "ws2_32.lib")

SOCKET sock;

extern "C" __declspec(dllexport) void mymemcpy(char *p_dst, const char *p_src, size_t length)
{
  for (size_t i = 0; i < length; i++)
  {
    p_dst[i] = p_src[i];
  }
}

extern "C" __declspec(dllexport) void count_null_bytes(const char *p_src, size_t len)
{
  char   text[1024];
  size_t j = 0;
  mymemcpy(text, p_src, len);

  for (size_t i = 0; i < len; i++)
    if (text[i])
      j++;

  printf("received data with %zd null bytes\n", j);
}

int main()
{
  WSAData wsadata;
  if (WSAStartup(MAKEWORD(2, 2), &wsadata)) {
    printf("failed to intiialize windows sockets api\n");
    return 1;
  }

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock == SOCKET_ERROR) {
    printf("failed to open socket. LastError() = %d\n", WSAGetLastError());
    return 1;
  }

  sockaddr_in localaddr;
  localaddr.sin_family = AF_INET;
  localaddr.sin_addr.s_addr = INADDR_ANY;
  localaddr.sin_port = 27000; //server port
  if (bind(sock, (sockaddr *)&localaddr, sizeof(localaddr)) == SOCKET_ERROR) {
    printf("failed to bind socket. LastError() = %d\n", WSAGetLastError());
    return 1;
  }

  static char buf[2048];
  printf("Server started\n");
  while (1) {
    sockaddr_in from;
    int fromlen = sizeof(from);
    int nbytes = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr *)&from, &fromlen);
    if (nbytes == SOCKET_ERROR) {
      printf("receiving data from %s failed!\n", inet_ntoa(from.sin_addr));
      continue;
    }
    printf("receiving %d bytes from %s\n", nbytes, inet_ntoa(from.sin_addr));
    count_null_bytes(buf, (size_t)nbytes);
  }
  closesocket(sock);
  WSACleanup();
  return 0;
}