#include<string.h>
#include<sys/socket.h>
#include<sys/stat.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<iostream>
#include<algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>

#define MAGIC_NUMBER_LENGTH 6
#define HEADER_LENGTH 12
#define OPEN_CONN_REQUEST 0xA1
#define OPEN_CONN_REPLY 0xA2
#define LIST_REQUEST 0xA3
#define LIST_REPLY 0xA4
#define GET_REQUEST 0xA5
#define GET_REPLY 0xA6
#define FILE_DATA 0xFF
#define PUT_REQUEST 0xA7
#define PUT_REPLY 0xA8
#define SHA_REQUEST 0xA9
#define SHA_REPLY 0xAA
#define QUIT_REQUEST 0xAB
#define QUIT_REPLY 0xAC

const char* magic_number = "\xc1\xa1\x10""ftp";

struct myftp_header
{
    char m_protocol[MAGIC_NUMBER_LENGTH];   /* protocol magic number (6 bytes) */
    uint8_t m_type;                            /* type (1 byte) */
    uint8_t m_status;                          /* status (1 byte) */
    uint32_t m_length;                  /* length (4 bytes) in Big endian*/
} __attribute__ ((packed));

//for headers
void set_header(struct myftp_header &header,uint8_t type,uint8_t status,uint32_t length)
{
    
    memcpy(header.m_protocol,magic_number,6);
    header.m_type = type;
    header.m_status = status;
    header.m_length = htonl(length);   
}
int check_header(struct myftp_header &header)
{
    return !memcmp(header.m_protocol,magic_number,MAGIC_NUMBER_LENGTH);
}


//for big files
void safe_send(int sock,myftp_header* header, int len,int d)
{
    size_t ret = 0;
    while (ret < len)
    {
        size_t b = send(sock, header + ret, len - ret, 0);
        ret += b;
    }
}
 
void safe_send(int sock,char* buffer, int len,int d)
{
    size_t ret = 0;
    while (ret < len)
    {
        size_t b = send(sock, buffer + ret, len - ret, 0);
        ret += b; 
    }
}

void safe_recv(int sock,myftp_header* buffer, int len,int d)
{
    size_t ret = 0;
    while (ret < len)
    {
        size_t b = recv(sock, buffer + ret, len - ret, 0);
        ret += b; 
    }
}
 
void safe_recv(int sock,char* buffer, int len,int d)
{
    size_t ret = 0;
    while (ret < len)
    {
        size_t b = recv(sock, buffer + ret, len - ret, 0);
        ret += b; 
    }
}