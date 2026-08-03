#ifndef CoreBridgeH
#define CoreBridgeH

#include <System.hpp>

struct bb_identity;

class TCoreBridge
{
private:
    TCoreBridge();
    ~TCoreBridge();
    TCoreBridge(const TCoreBridge &) = delete;
    TCoreBridge &operator=(const TCoreBridge &) = delete;

    void *FModule;
    bb_identity *FIdentity;
    UnicodeString FLastError;

    bool EnsureLoaded();
public:
    static TCoreBridge &Instance();
    bool Unlock(const UnicodeString &mnemonic);
    bool GenerateMnemonic(UnicodeString &mnemonic);
    void Lock();
    bool IsUnlocked() const { return FIdentity != nullptr; }
    const UnicodeString &LastError() const { return FLastError; }
};

#endif

