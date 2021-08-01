#include "systemendianess.h"

//------------------------------------------------------------------------------
// class SystemEndianess implementation
//------------------------------------------------------------------------------
//      struct SystemEndianess::Initializer implementation
//------------------------------------------------------------------------------
//      Constructor
//------------------------------------------------------------------------------
SystemEndianess::Initializer::Initializer(){
    // So fast, no need to protect it from multiple initializazions
    unsigned short shortValue = 0x1;
    unsigned char *charPtr = reinterpret_cast<unsigned char *>(&shortValue);
    _littleEndian = *charPtr == 0x1;
}
//------------------------------------------------------------------------------
// Static data
bool SystemEndianess::_littleEndian;
//------------------------------------------------------------------------------


