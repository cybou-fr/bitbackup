#ifndef CoreBridgeH
#define CoreBridgeH

#include <System.hpp>
#include <cstddef>
#include <vector>

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
    bool SealState(const void *plain, std::size_t plainLength,
                   std::vector<unsigned char> &sealed);
    bool OpenState(const void *sealed, std::size_t sealedLength,
                   std::vector<unsigned char> &plain);
    void Lock();
    bool IsUnlocked() const { return FIdentity != nullptr; }
    const UnicodeString &LastError() const { return FLastError; }
};

#endif
