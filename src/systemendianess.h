#ifndef SYSTEMENDIANESS_H
#define SYSTEMENDIANESS_H

//------------------------------------------------------------------------------
// Forwards
//------------------------------------------------------------------------------
//class SystemEndianessInitializer;


//------------------------------------------------------------------------------
// class SystemEndianess
//------------------------------------------------------------------------------
class SystemEndianess{
public:
    // Accessors
    static inline bool littleEndian() { return _littleEndian; }
    static inline bool bigEndian() { return !_littleEndian; }
    // Types
    struct Initializer {
        Initializer();
    };
private:
    friend struct Initializer;
    // Private constructor (unimplemented!)
    SystemEndianess();
    // Data
    static bool _littleEndian;
};

static SystemEndianess::Initializer __compilation_unit_SystemEndianess_Initializer;

#endif // SYSTEMENDIANESS_H

