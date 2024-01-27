#include "router_prototype.h"
#include <stdint.h>
#include <map>
#include <vector>
#include <iostream>
#include <string>
#include <cstring>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <algorithm>

#define HEADER_SIZE 12
#define MAX_PACKET 16384

#define TYPE_DV 0x00
#define TYPE_DATA 0x01
#define TYPE_CONTROL 0x02
#define TYPE_PORT 0x03

#define TRIGGER_DV_SEND 0x0
#define RELEASE_NAT_ITEM 0x1
#define PORT_VALUE_CHANGE 0x2
#define ADD_HOST 0x3
#define BLOCK_ADDR 0x5
#define UNBLOCK_ADDR 0x6

using namespace std;
class Header 
{
public:
    uint32_t src;
    uint32_t dst;
    uint8_t type;
    uint16_t length;
};
class Dis_Next 
{
public:
    int32_t distance;
    int32_t next;
};
class dv_entry 
{
public:
    uint32_t ip;
    int32_t distance;
    int next;
    int opposite;
};

class Router : public RouterBase 
{
public:
    bool update;
    int port_num; 
    int external_port; 
    int pub_pos; 
    int way_num; 
    uint32_t external_addr; 
    uint32_t external_mask;
    uint32_t available_addr;
    uint32_t available_mask;
    map<uint32_t, Dis_Next> DV_table; 
    map<uint32_t, Dis_Next> send_dv_table; 
    map<uint32_t, uint32_t> NAT_table; 
    map<int, int> port_table; 
    vector<bool> pub_use; 
    vector<int> w; 
    vector<uint32_t> block_list; 

   
    void router_init(int port_num, int external_port, char* external_addr, char* available_addr);
    int router(int in_port, char* packet);

    int data(int in_port, Header header, char* payload, char* packet);
    int ctrl(int in_port, Header header, char* payload, char* packet);
    int port(int in_port, Header header, char* payload, char* packet);
    int dv(int in_port, Header header, char* payload, char* packet);
    int port_change(int port, int value, Header header, char* packet);
    bool check_firewall(uint32_t ip);
    Dis_Next dv_search(uint32_t dst);
    uint32_t* nat(uint32_t in,int mode);
   
};