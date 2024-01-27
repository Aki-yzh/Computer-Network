#include "myftp.h"
using namespace std;
char buf[32] = {0};    
string IP;
int flag = 0;//flag for connection
int server;

void open()
{
    struct sockaddr_in addr;
    bzero(&addr,sizeof(addr));
    addr.sin_family = AF_INET;
    server = socket(AF_INET,SOCK_STREAM,0);
    memset(buf,0,sizeof(buf));
    cin>>buf;
    inet_pton(AF_INET,buf,&addr.sin_addr);
    string IP_0;
    IP_0 = strcat(buf,":");
    memset(buf,0,sizeof(buf));
    cin>>buf;
    IP_0.append(buf);
    addr.sin_port=htons(atoi(buf));
    int ret =connect(server,(struct sockaddr*)&addr,sizeof(addr));
    if(ret<0)
    {
        cout<<"Connection Failed_1"<<endl;
    }
    else
    {
        struct myftp_header header;    
        set_header(header,OPEN_CONN_REQUEST,0,HEADER_LENGTH);
        safe_send(server,&header,HEADER_LENGTH,0);
        safe_recv(server,&header,HEADER_LENGTH,0);
        if(check_header(header) && header.m_type == OPEN_CONN_REPLY&&header.m_status==1)
        {      
            flag = 1;  
            IP = IP_0;
            cout<<"Connect Successfully"<<endl;
        }
        else
        {
            cout<<"Connection Failed_2"<<endl;
        }      
    }
    
}
void ls()
{
    struct myftp_header header;
    set_header(header,LIST_REQUEST,0,HEADER_LENGTH);
    safe_send(server,&header,HEADER_LENGTH,0);
    safe_recv(server,&header,HEADER_LENGTH,0);
    uint32_t length = ntohl(header.m_length);
    char * payload =(char *) malloc(length-HEADER_LENGTH);
    safe_recv(server,payload,length-HEADER_LENGTH,0);
    cout<<"------------------File List Start-----------------"<<endl;
    printf("%s",payload);
    cout<<"------------------File List End-----------------"<<endl;
    free(payload);
}
void get()
{
    cin>>buf;
    struct myftp_header header;
    set_header(header,GET_REQUEST,0,HEADER_LENGTH+strlen(buf)+1);
    safe_send(server,&header,HEADER_LENGTH,0);
    safe_send(server,buf,strlen(buf)+1,0);
    safe_recv(server,&header,HEADER_LENGTH,0);
    if(check_header(header)&& header.m_type == GET_REPLY&& header.m_status == 1)
    {  
        safe_recv(server,&header,HEADER_LENGTH,0);    
        int length = ntohl(header.m_length)-HEADER_LENGTH;
        FILE *file = fopen(buf,"wb");
        while(true)
        {
            char temp[1024] = {0};
            safe_recv(server,temp,min(1024,length),0);
            fwrite(temp,sizeof(char),min(1024,length),file);
            length -= 1024;
            if(length <= 0)
            { 
                break;
            }
        }
        fclose(file);
        cout<<"Get Successfully"<<endl;
    }
}
void put()
{
    cin>>buf;
    struct myftp_header header;
    if(access(buf,F_OK) == 0)
    {
        struct stat statbuf;
        stat(buf,&statbuf);
        set_header(header,PUT_REQUEST,0,HEADER_LENGTH+strlen(buf)+1);
        safe_send(server,&header,HEADER_LENGTH,0);
        safe_send(server,buf,strlen(buf)+1,0);
        safe_recv(server,&header,HEADER_LENGTH,0);
        set_header(header,FILE_DATA,0,HEADER_LENGTH+statbuf.st_size);
        safe_send(server,&header,HEADER_LENGTH,0);
        unsigned char temp[1024];
        FILE *file = fopen(buf,"rb");
        int length = 0;
        while(true)
        {
            length = fread(temp,sizeof(char),1024,file);
            if(length == 0) break;
            send(server,temp,length,0);
        }
        cout<<"Put Successfully!"<<endl;
        fclose(file);
        }
        else
        {
            cout<<"Not found"<<endl;
        }
}
void sha256()
{
    cin>>buf;
    struct myftp_header header;
    set_header(header,SHA_REQUEST,0,HEADER_LENGTH+strlen(buf)+1);
    safe_send(server,&header,HEADER_LENGTH,0);
    safe_send(server,buf,strlen(buf)+1,0);
    safe_recv(server,&header,HEADER_LENGTH,0);
    if(check_header(header)&& header.m_type == SHA_REPLY&& header.m_status == 1)
    {  
        uint32_t length = ntohl(header.m_length);
        char* payload =(char *) malloc(length-HEADER_LENGTH);
        safe_recv(server,payload,length-HEADER_LENGTH,0);
        cout<<"------------------Sha256 Result Start-----------------"<<endl;
        printf("%s",payload);
        cout<<"------------------Sha256 Result End-----------------"<<endl;
        free(payload);
    }
   
}
void quit()
{
    struct myftp_header header;
    set_header(header,QUIT_REQUEST,0,HEADER_LENGTH);
    safe_send(server,&header,HEADER_LENGTH,0);
    if(recv(server,&header,HEADER_LENGTH,0))
    {
        if(header.m_type == QUIT_REPLY)
        {   
            close(server);
            cout<<"Quit Successfully"<<endl;
        }
    }
    else 
    {
        exit(0);
    }
}
void command_line()
{
    if(!flag)
    {
        cout<<"client(none)>";
    }
    else
    {
        cout<<"clent(";
        cout<<IP;
        cout<<")>";
    }
}

int main()
{
    command_line();
    while(cin>>buf)
    {
        if(memcmp(buf,"open",4) == 0 && flag == 0)
        {
            open();
            continue;
        }
        else if(!flag)
        {
            cout<<"Establish Connection First"<<endl;
            continue;
        }
        else if(memcmp(buf,"ls",2)==0)
        {
            ls();
            continue;
        }
        else if(memcmp(buf,"get",3)==0)
        {
            get();
            continue;
        }
        else if(memcmp(buf,"put",3)==0)
        {
            put();
            continue;
        }
        else if(memcmp(buf,"sha256",6)==0)
        {
            sha256();
            continue;
        }
        else if(memcpy(buf,"quit",4)==0)
        {
            quit();
        }
        else
        {
            cout<<"Please Use Right Command"<<endl;
        }
        command_line();
    }
    return 0;
}
