#include "myftp.h"
using namespace std;

void open(int client,struct myftp_header header)
{
    set_header(header,OPEN_CONN_REPLY,1,HEADER_LENGTH);
    safe_send(client,&header,HEADER_LENGTH,0);
}
void ls(int client,struct myftp_header header)
{
    FILE * file;
    char ls_answer[2048] = {0};
    int length = 0;
    file = popen("ls","r");
    length = fread(ls_answer,1,2048,file);
    ls_answer[length] = 0;
    set_header(header,LIST_REPLY,0,HEADER_LENGTH+length+1);
    safe_send(client,&header,HEADER_LENGTH,0);
    safe_send(client,ls_answer,length+1,0);
}
void get(int client,struct myftp_header header,uint32_t length)
{
    char filename[16];
    safe_recv(client,filename,length-HEADER_LENGTH,0);
    if(access(filename,F_OK) == 0)
    {
        set_header(header,GET_REPLY,1,HEADER_LENGTH);
        safe_send(client,&header,HEADER_LENGTH,0);
        struct stat statbuf;
        stat(filename,&statbuf);
        set_header(header,FILE_DATA,0,HEADER_LENGTH+statbuf.st_size);
        safe_send(client,&header,HEADER_LENGTH,0);
        int length = 0;
        FILE *file = fopen(filename,"rb");
        while(true)
        {   
            unsigned char temp[1024];
            length = fread(temp,sizeof(char),1024,file);
            if(length == 0) break;
            send(client,temp,length,0);
        }
        fclose(file);
    }
    else
    {
        set_header(header,GET_REPLY,0,HEADER_LENGTH);
        safe_send(client,&header,HEADER_LENGTH,0);
    }
}
void put(int client,struct myftp_header header,uint32_t length)
{
    char filename[16];
    safe_recv(client,filename,length-HEADER_LENGTH,0);
    set_header(header,PUT_REPLY,0,HEADER_LENGTH);
    safe_send(client,&header,HEADER_LENGTH,0);
    FILE *file = fopen(filename,"wb"); 
    safe_recv(client,&header,HEADER_LENGTH,0);
    int f_length = ntohl(header.m_length)-HEADER_LENGTH;
    while(true)
    {
        char temp[1024] = {0}; 
        safe_recv(client,temp,min(f_length,1024),0);
        fwrite(temp,sizeof(char),min(f_length,1024),file);
        f_length -= 1024;
        if(f_length <= 0) break;
    }
    fclose(file);
}
void sha256(int client,struct myftp_header header,uint32_t length)
{
    char filename[16];
    safe_recv(client,filename,length-HEADER_LENGTH,0);
    if(access(filename,F_OK) == 0)
    {
        set_header(header,SHA_REPLY,1,HEADER_LENGTH);
        safe_send(client,&header,HEADER_LENGTH,0);
        char command[256];
        sprintf(command, "sha256sum %s", filename);
        FILE *file = popen(command,"r");
        if (file == NULL)
        {
           cout<<"Error"<<endl;
        }
        char temp[256];
        memset(temp, 0, sizeof(temp));
        fread(temp, sizeof(char), sizeof(temp) - 1, file);
        char *result = (char*) malloc(strlen(temp) + 1);
        strcpy(result, temp);
        result[strlen(temp)] = '\0'; 
        length = strlen(result);
        set_header(header,FILE_DATA,0,HEADER_LENGTH+length+1);
        safe_send(client,&header,HEADER_LENGTH,0);
        safe_send(client,result,length+1,0);
        pclose(file);
    }
    else
    {
        set_header(header,SHA_REPLY,0,HEADER_LENGTH);
        safe_send(client,&header,HEADER_LENGTH,0);
    }
}
void quit(int client,struct myftp_header header)
{
    set_header(header,QUIT_REPLY,0,HEADER_LENGTH);
    safe_send(client,&header,HEADER_LENGTH,0);
    sleep(25);
    close(client);
}
void *deal(void* argument)
{
    while(true)
    {  
        int client;
        client = *((int *)(argument));
        struct myftp_header header;
        safe_recv(client,&header,HEADER_LENGTH,0);
        uint8_t type=header.m_type;
        uint32_t length=ntohl(header.m_length);
        if(type == OPEN_CONN_REQUEST)
        {
            open(client,header);
            continue;
        }
        if(type == LIST_REQUEST)
        {
            ls(client,header);
            continue;
        }
        if(type == GET_REQUEST)
        {
           get(client,header,length);
           continue;
        }
        if(type == PUT_REQUEST)
        {
           put(client,header,length);
           continue;
        }
        if(type == SHA_REQUEST)
        {
            sha256(client,header,length);
            continue;
        }
        if(type == QUIT_REQUEST)
        {
            quit(client,header);
            break;
        }
    }
}


int main(int argc, char ** argv) {
    if(argc != 3)
    {
        cout<<"Please Retry"<<endl;
        exit(0);
    }
    int sock = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    inet_pton(AF_INET,argv[1],&addr.sin_addr);
    addr.sin_port = htons(atoi(argv[2]));
    bind(sock,(struct sockaddr*)&addr,sizeof(addr));
    listen(sock,256);
    int client;
    while(true)
    {
        client = accept(sock,NULL,NULL);
        pthread_t thread;
        pthread_create(&thread,NULL,&deal,(void*)&client);
    }
}
