#include "switch.h"
using namespace std;
const char FRAME_DELi = 0xDE;

SwitchBase* CreateSwitchObject() {
  // TODO : Your code.
   return new Switch();
}


int PackFrame(char* unpacked_frame, char* packed_frame, int frame_length)
{
    int packed_length = 0;
    uint8_t parity = 0;
    packed_frame[packed_length] = FRAME_DELi;
    packed_length++;
    for (int i = 0; i < frame_length; ++i) 
    {
        if (unpacked_frame[i] == FRAME_DELi) 
        {
            packed_frame[packed_length] = FRAME_DELi;
            packed_length++;
        }
        packed_frame[packed_length] = unpacked_frame[i];
        packed_length++;
    }
    for(int i=0;i<packed_length;i++)
    {
        for(int j=0;j<8;j++)
        {
            parity ^= (packed_frame[i] >> j) & 1;
        }
    }
    packed_frame[packed_length] = parity == 0 ? 0x00 : 0x01;
    packed_length++;
    return packed_length;
}
int UnpackFrame(char* unpacked_frame, char* packed_frame, int frame_length)
{
    int unpacked_length = 0;
    uint8_t parity = 0;  
    if (packed_frame[0] != FRAME_DELi) 
    {
        return -1;
    }
    for (int i = 0; i < frame_length; i++)
    {
        char c = packed_frame[i];
        for (int j = 0; j < 8; j++) 
        {
            parity ^= (c >> j) & 1;
        }
    }
    if(parity != 0 ) 
        return -1;
    for (int i = 1; i < frame_length - 1; i++) 
    {
        if (packed_frame[i] == FRAME_DELi) 
        {
            i++;
            if(packed_frame[i] != FRAME_DELi)
                return -1;
        }
        unpacked_frame[unpacked_length] = packed_frame[i];
        unpacked_length++;
    }
    return unpacked_length;
}