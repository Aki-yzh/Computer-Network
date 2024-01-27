#include "router.h"
using namespace std;


RouterBase* create_router_object()
{
    return new Router;
}

void Router::router_init(int port_num, int external_port, char* external_addr, char* available_addr)
{
    char* token;
    uint32_t external_ip, available_ip;
    pub_pos = 0;
    way_num = 0;
    block_list.clear();
    this->port_num = port_num;
    this->external_port = external_port;
    w.resize(port_num + 1, -1);
    w[1] = 0;
    w[this->external_port] = 0;
    if (external_port == 0)
    {
        external_mask = 0;
        available_mask = 0;
        this->external_addr = 0;
        this->available_addr = 0;
        return;
    }
    token = strtok(external_addr, "/");
    inet_pton(AF_INET, token, &external_ip);
    this->external_addr = ntohl(external_ip);
    token = strtok(NULL, "/");
    external_mask = ((1 << (atoi(token))) - 1) << (32 - (atoi(token)));
    this->external_addr &= ((1 << (atoi(token))) - 1) << (32 - (atoi(token)));
    DV_table.insert({this->external_addr, Dis_Next{0, this->external_port}});
    send_dv_table.insert({this->external_addr, Dis_Next{0, this->external_port}});
    token = strtok(available_addr, "/");
    inet_pton(AF_INET, token, &available_ip);
    this->available_addr = ntohl(available_ip);
    uint32_t   bit = atoi(strtok(NULL, "/"));
    available_mask = ((1 << (bit)) - 1) << (32 - (bit));
    this->available_addr &= ((1 << (bit)) - 1) << (32 - (bit));
    pub_use.resize(1 << (32 - (bit)), false);
    return;
}/*router init*/
int Router::router(int in_port, char* packet)
{
    Header header;
    int ret = -1;
    memcpy(&header, packet, HEADER_SIZE);
    char* payload = new char[header.length];
    memcpy(payload, packet + HEADER_SIZE, header.length);
    if (header.type == TYPE_DV)
    {
        ret = dv(in_port, header, payload, packet);
    }
    else if (header.type == TYPE_DATA)
    {
        ret = data(in_port, header, payload, packet);
    }
    else if (header.type == TYPE_CONTROL)
    {
        ret = ctrl(in_port, header, payload, packet);
    }
    else if (header.type == TYPE_PORT)
    {
        ret = port(in_port, header, payload, packet);
    }
    else
    {
        ret = -1;
    }
    delete[] payload;
    return ret;
}/*根据传入的输出端口号和数据包头部信息来调用不同的处理函数*/

int Router::data(int in_port, Header header, char* payload, char* packet)
{
    if (check_firewall(u_int32_t(header.src)))
    {
        return -1;
    }
    uint32_t dst = ntohl(header.dst);
    uint32_t src = ntohl(header.src);
    if(this->external_port != 0 && ((src & (this->external_mask)) == this->external_addr))
    {
        uint32_t* dst_in = nat(dst,1);
        if (!dst_in)
        {
            return -1;
        }
        dst = *dst_in;
        delete dst_in;
        Header new_header{header.src, htonl(dst), header.type, header.length};
        memset(packet, 0, HEADER_SIZE + header.length);
        memcpy(packet, &new_header, HEADER_SIZE);
        memcpy(packet + HEADER_SIZE, payload, new_header.length);
    }
    Dis_Next dn = dv_search(dst);
    if (dn.distance == -1 && dn.next == -1)
    {
        return 1;
    }
    if (dn.distance == 0 && this->external_port != 0 && ((dst & (this->external_mask)) == this->external_addr))
    {
        uint32_t* src_pub = nat(src, 0);
        if (!src_pub)
        {
            return -1;
        }
        Header new_header{htonl(*src_pub), htonl(dst), header.type, header.length};
        memset(packet, 0, HEADER_SIZE + header.length);
        memcpy(packet, &new_header, HEADER_SIZE);
        memcpy(packet + HEADER_SIZE, payload, new_header.length);
        return dn.next;
    }
    else
    {
        return dn.next;
    }
}/*处理数据类型的packet，先检查防火墙与外网，将源地址与目的地址进行转换，在路由表中寻找下一跳并转发*/
int Router::ctrl(int in_port, Header header, char* payload, char* packet)
{
    char* internal_ip, *token;
    uint32_t in_ip, ip;
    int port, value;
    token = strtok(payload, " ");
    int ctrl_type = atoi(token);
    if (ctrl_type == TRIGGER_DV_SEND)
    {
        if (send_dv_table.size() > 0 && way_num > 0)
        {
            memset(packet, 0, HEADER_SIZE + header.length);
            size_t dv_num{send_dv_table.size()};
            int i{0};
            dv_entry* dv_p{new dv_entry[dv_num]};
            auto it = send_dv_table.begin();
            while (it != send_dv_table.end())
            {
                auto& entry = *it;
                dv_p[i].next = entry.second.next;
                dv_p[i].distance = entry.second.distance;
                dv_p[i].ip = entry.first;
                dv_p[i].opposite = port_table.find(entry.second.next) == port_table.end() ? -1 : port_table[entry.second.next];
                ++i;
                ++it;
            }
            Header header{0, 0, TYPE_DV, (uint16_t)(dv_num * sizeof(dv_entry))};
            memcpy(packet, &header, HEADER_SIZE);
            memcpy(packet + HEADER_SIZE, (char*)dv_p, header.length);
            delete[] dv_p;
            send_dv_table.clear();
            return 0;
        }
        else
            return -1;
    }
    else if (ctrl_type == RELEASE_NAT_ITEM)
    {
        internal_ip = strtok(NULL, " ");
        inet_pton(AF_INET, internal_ip, &in_ip);
        in_ip = ntohl(in_ip);
        if (NAT_table.find(in_ip) != NAT_table.end())
        {
            pub_use[NAT_table[in_ip] & ~(available_mask)] = false;
            NAT_table.erase(in_ip);
        }
        return -1;
    }
    else if (ctrl_type == PORT_VALUE_CHANGE)
    {
        token = strtok(NULL, " ");
        port = atoi(token);
        token = strtok(NULL, " ");
        value = atoi(token);
        return port_change(port, value, header, packet);
    }
    else if (ctrl_type == ADD_HOST)
    {
        token = strtok(NULL, " ");
        port = atoi(token);
        token = strtok(NULL, " ");
        inet_pton(AF_INET, token, &ip);
        ip = ntohl(ip);
        if (port > port_num)
        {
            return -1;
        }
        w[port] = 0;
        DV_table[ip] = Dis_Next{0, port};
        if (send_dv_table.find(ip) == send_dv_table.end())
            send_dv_table.insert({ip, DV_table[ip]});
        else
            send_dv_table[ip] = DV_table[ip];
        return -1;
    }
    else if (ctrl_type == BLOCK_ADDR)
    {
        token = strtok(NULL, " ");
        inet_pton(AF_INET, token, &ip);
        if (check_firewall(ip))
        {
            return -1;
        }
        block_list.push_back(ip);
        return -1;
    }
    else if (ctrl_type == UNBLOCK_ADDR)
    {
        token = strtok(NULL, " ");
        inet_pton(AF_INET, token, &ip);
        auto it = find(block_list.begin(), block_list.end(), ip);
        if (it != block_list.end())
        {
            block_list.erase(it);
        }
        return -1;
    }
    else
        return -1;
}/*控制消息的处理*/
int Router::port(int in_port, Header header, char* payload, char* packet)
{
    int op_port = *((int*)payload);
    if (port_table.find(in_port) == port_table.end())
        port_table.insert({in_port, op_port});
    else
        port_table[in_port] = op_port;
    return -1;
}/*更新port——table*/

int Router::dv(int in_port, Header header, char* payload, char* packet)
{
    int broadcast = -1;
    int i = 0;
    if (this->w[in_port] == -1)
        return -1;
    uint32_t entry_num = header.length / sizeof(dv_entry);
    if (entry_num == 0)
        return -1;
    dv_entry* dv_payload = new dv_entry[entry_num];
    memcpy(dv_payload, payload, header.length);
    while (i < entry_num)
    {
        int next = dv_payload[i].next;
        int opposite = dv_payload[i].opposite;
        uint32_t ip = dv_payload[i].ip;
        int32_t distance = dv_payload[i].distance;
        if (this->DV_table.find(ip) == this->DV_table.end()&&distance!=-1)
        {
            this->DV_table[ip] = Dis_Next{distance + this->w[in_port], in_port};
            if (this->send_dv_table.find(ip) == this->send_dv_table.end())
                this->send_dv_table.insert({ip, this->DV_table[ip]});
            else
                this->send_dv_table[ip] = this->DV_table[ip];
            broadcast = 0;
        }
        else
        {
            if (distance != -1)
            {
                if (this->DV_table[ip].distance != -1 && this->DV_table[ip].next == in_port)
                {
                    this->DV_table[ip] = Dis_Next{distance + this->w[in_port], in_port};
                    if (this->send_dv_table.find(ip) == this->send_dv_table.end())
                        this->send_dv_table.insert({ip, this->DV_table[ip]});
                    else
                        this->send_dv_table[ip] = this->DV_table[ip];
                    broadcast = 0;
                }
                if (this->DV_table[ip].distance == -1 || this->DV_table[ip].distance > distance + this->w[in_port])
                {
                    if (in_port != opposite || this->port_table[opposite] != next)
                    {
                        this->DV_table[ip] = Dis_Next{distance + this->w[in_port], in_port};
                        if (this->send_dv_table.find(ip) == this->send_dv_table.end())
                            this->send_dv_table.insert({ip, this->DV_table[ip]});
                        else
                            this->send_dv_table[ip] = this->DV_table[ip];
                        broadcast = 0;
                    }
                }
                if (this->DV_table[ip].distance != -1 && this->DV_table[ip].next != in_port && this->DV_table[ip].distance + this->w[in_port] < distance)
                {
                    if (this->send_dv_table.find(ip) == this->send_dv_table.end())
                        this->send_dv_table.insert({ip, this->DV_table[ip]});
                    else
                        send_dv_table[ip] = DV_table[ip];
                    if (broadcast == -1)
                        broadcast = in_port;
                    else if (broadcast > 0)
                        broadcast = 0;
                }
            }
            else if (DV_table[ip].distance != -1)
            {
                if (DV_table[ip].next != in_port)
                {
                    if (send_dv_table.find(ip) == send_dv_table.end())
                        send_dv_table.insert({ip, DV_table[ip]});
                    else
                        send_dv_table[ip] = DV_table[ip];
                    if (broadcast == -1)
                        broadcast = in_port;
                    else if (broadcast > 0)
                        broadcast = 0;
                }
                else
                {
                    DV_table[ip].distance = -1;
                    if (send_dv_table.find(ip) == send_dv_table.end())
                        send_dv_table.insert({ip, DV_table[ip]});
                    else
                        send_dv_table[ip] = DV_table[ip];
                    broadcast = 0;       
                }
            }
        }
        ++i;
    }
    if (send_dv_table.size() > 0 && way_num > 0)
    {
        memset(packet, 0, HEADER_SIZE + header.length);
        size_t dv_num{send_dv_table.size()};
        int i{0};
        dv_entry* dv_p{new dv_entry[dv_num]};
        auto it = send_dv_table.begin();
        while (it != send_dv_table.end())
        {
            auto& entry = *it;
            dv_p[i].next = entry.second.next;
            dv_p[i].distance = entry.second.distance;
            dv_p[i].ip = entry.first;
            dv_p[i].opposite = port_table.find(entry.second.next) == port_table.end() ? -1 : port_table[entry.second.next];
            ++i;
            ++it;
        }
        Header header{0, 0, TYPE_DV, (uint16_t)(dv_num * sizeof(dv_entry))};
        memcpy(packet, &header, HEADER_SIZE);
        memcpy(packet + HEADER_SIZE, (char*)dv_p, header.length);
        delete[] dv_p;
        send_dv_table.clear();
        delete[] dv_payload;
        return broadcast;
    }
    delete[] dv_payload;
    return -1;
}
/*DV算法*/

int Router::port_change(int port, int value, Header header, char* packet)
{
    if (port > port_num || port <= 1)
    {
        return -1;
    }
    if (w[port] != value)
    {
        int old_value = w[port];
        w[port] = value;
        if (value == -1 && old_value > 0)
            way_num -= 1;
        else if (value > 0 && old_value == -1)
        {
            way_num += 1;
            auto it = DV_table.begin();
            while (it != DV_table.end())
            {
                if (send_dv_table.find(it->first) == send_dv_table.end())
                    send_dv_table.insert({it->first, DV_table[it->first]});
                else
                    send_dv_table[it->first] = DV_table[it->first];
                ++it;
            }
        }
        auto it = DV_table.begin();
        while (it != DV_table.end())
        {
            auto& entry = *it;
            if (entry.second.next == port)
            {
                if (value == -1)
                {
                    entry.second.distance = -1;
                    if (send_dv_table.find(entry.first) == send_dv_table.end())
                        send_dv_table.insert({entry.first, DV_table[entry.first]});
                    else
                        send_dv_table[entry.first] = DV_table[entry.first];
                    port_table.erase(port);
                }
                else if (old_value != -1)
                {
                    entry.second.distance -= (old_value - value);
                    if (send_dv_table.find(entry.first) == send_dv_table.end())
                        send_dv_table.insert({entry.first, DV_table[entry.first]});
                    else
                        send_dv_table[entry.first] = DV_table[entry.first];
                }
            }
            ++it;
        }
        if (old_value == -1)
        {
            memset(packet, 0, HEADER_SIZE + header.length);
            Header header{0, 0, TYPE_PORT, sizeof(int)};
            memcpy(packet, &header, HEADER_SIZE);
            memcpy(packet + HEADER_SIZE, (char*)&port, header.length);
            return port;
        }
    }
    return -1;
}/*处理端口变化，更新端口权重与路由表*/

bool Router::check_firewall(uint32_t ip)
{
    if (find(block_list.begin(), block_list.end(), ip) != block_list.end())
    {
        return true;
    }
    return false;
}/*检查防火墙*/

uint32_t* Router::nat(uint32_t in,int mode)
{
    if(mode==0)
    {
        if(this->NAT_table.find(in) != this->NAT_table.end())
        {
            return &(this->NAT_table[in]);
        }
        else
        {
            size_t pub_size = pub_use.size();
            int i = 0;
            while (i < pub_size)
            {
                int idx = (pub_pos + i) % pub_size;
                if (!pub_use[idx])
                {
                    uint32_t pub_ip = available_addr | idx;
                    pub_use[idx] = true;
                    pub_pos = (idx + 1) % pub_size;
                    this->NAT_table.insert({in, pub_ip});
                    return &(this->NAT_table[in]);
                }
                ++i;
            }
        }
        return nullptr;
    }
    else if(mode ==1)
    {
        int idx = in & (~(this->available_mask));
        if(!pub_use[idx])
            return nullptr;
        auto it = this->NAT_table.begin();
        while (it != this->NAT_table.end()) 
        {
            if (it->second == in) {
                uint32_t* ret = new uint32_t;
                *ret = it->first;
                return ret;
            }
            ++it;
        }
        return nullptr;
    }   
    return nullptr;
}/*NAT地址转换，0内转公，1反之*/

Dis_Next Router::dv_search(uint32_t dst)
{
    Dis_Next dn = {-1, -1};    
    if((dst & 0xff000000) != 0xa000000)
    {
        uint32_t mask = 0xffffffff;
        auto it = this->DV_table.begin();
        while (it != this->DV_table.end())
        {
            if ((dst & it->first) == it->first&&(it->first ^ dst) < mask)
            {
                dn.next = it->second.next;
                mask = it->first ^ dst;
                dn.distance = it->second.distance;
            }
            ++it;
        }
    }
    else
    {
        if(this->DV_table.find(dst) != this->DV_table.end()&&this->DV_table[dst].distance != -1)
        {
            dn.next = this->DV_table[dst].next;
            dn.distance = this->DV_table[dst].distance;  
        }
    }
    return dn;
}
/*路由表查找下一跳*/