#ifndef COMPNET_LAB4_SRC_SWITCH_H
#define COMPNET_LAB4_SRC_SWITCH_H

#include "types.h"
#include <iostream>
#include <vector>
#include <algorithm>
using namespace std;

class SwitchBase {
 public:
  SwitchBase() = default;
  ~SwitchBase() = default;

  virtual void InitSwitch(int numPorts) = 0;
  virtual int ProcessFrame(int inPort, char* framePtr) = 0;
};

extern SwitchBase* CreateSwitchObject();
extern int PackFrame(char* unpacked_frame, char* packed_frame, int frame_length);
extern int UnpackFrame(char* unpacked_frame, char* packed_frame, int frame_length);

// TODO : Implement your switch class.
class table_item
{
public:
  int port;
  mac_addr_t mac;
  int counter;
  table_item()
  {
    port = 0;
    memset(mac,0,ETH_ALEN);
    counter = 10;
  }
  table_item(int port_,mac_addr_t mac_)
  {
    port = port_;
    memcpy(mac,mac_,ETH_ALEN);   
    counter = 10;
  }
};

class Switch : public SwitchBase
{
public:
  int portNum;
  vector<table_item> table;
  void InitSwitch(int numPorts) override
  {
    portNum = numPorts;
  }
  int ProcessFrame(int inPort, char* framePtr) override
  {
    ether_header_t header;
    memcpy(&header,framePtr,16);
    bool i = false;
    for(auto it = table.begin(); it != table.end(); ++it)
    {
      if(equal(it->mac, it->mac + 6, header.ether_src))
      {
        it->counter = 10;
        i = true;
        break;
      }
    }
    if(!i)
    {
      table.push_back(table_item(inPort,header.ether_src));
    }
   if(header.ether_type == ETHER_CONTROL_TYPE)
    {
      for (auto it = table.begin(); it != table.end();++it) 
      {
        it->counter--;
        if (it->counter <= 0) 
          it = table.erase(it);
      }
      return -1;
    }
    if(header.ether_type == ETHER_DATA_TYPE)
    {
      for (auto it = table.begin(); it != table.end();++it) 
      {
        if(equal(it->mac,it->mac+6,header.ether_dest))
        {
          if(it->port != inPort)
            return it->port;
          else
            return -1;
        }
      }
      return 0;
    }
    return -1;
  }
};
#endif  // ! COMPNET_LAB4_SRC_SWITCH_H
