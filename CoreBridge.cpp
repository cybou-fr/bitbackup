#include <System.hpp>
#include <System.SysUtils.hpp>
#include <windows.h>

#include "CoreBridge.h"
#include "bbcore/include/bbcore/bbcore.h"

namespace {

typedef bb_status (BB_CALL *TInit)();
typedef const char *(BB_CALL *TStatusText)(bb_status);
typedef bb_status (BB_CALL *TMnemonicNew)(unsigned, char *, size_t, size_t *);
typedef bb_status (BB_CALL *TMnemonicValidate)(const char *);
typedef bb_status (BB_CALL *TIdentityOpen)(const char *, const char *, uint32_t, bb_identity **);
typedef void (BB_CALL *TIdentityFree)(bb_identity *);

struct TApi {
    TInit Init = nullptr;
    TStatusText StatusText = nullptr;
    TMnemonicNew MnemonicNew = nullptr;
    TMnemonicValidate MnemonicValidate = nullptr;
    TIdentityOpen IdentityOpen = nullptr;
    TIdentityFree IdentityFree = nullptr;
};

TApi Api;

template <typename T>
bool Resolve(HMODULE module, const char *name, T &target)
{
    target = reinterpret_cast<T>(GetProcAddress(module, name));
    return target != nullptr;
}

UnicodeString StatusMessage(bb_status status)
{
    if (Api.StatusText == nullptr) return L"bbcore returned an unknown error";
    const char *text = Api.StatusText(status);
    return text == nullptr ? L"bbcore returned an unknown error"
                           : UnicodeString(UTF8String(text));
}

}  // namespace

TCoreBridge::TCoreBridge() : FModule(nullptr), FIdentity(nullptr) {}

TCoreBridge::~TCoreBridge()
{
    Lock();
    if (FModule != nullptr) FreeLibrary(static_cast<HMODULE>(FModule));
}

TCoreBridge &TCoreBridge::Instance()
{
    static TCoreBridge value;
    return value;
}

bool TCoreBridge::EnsureLoaded()
{
    if (FModule != nullptr) return true;

    HMODULE module = LoadLibraryW(L"bbcore.dll");
    if (module == nullptr) {
        const UnicodeString developmentPath =
            ExpandFileName(ExtractFilePath(ParamStr(0)) + L"..\\..\\build\\windows\\Release\\bbcore.dll");
        module = LoadLibraryW(developmentPath.c_str());
    }
    if (module == nullptr) {
        FLastError = L"bbcore.dll was not found next to the application.";
        return false;
    }

    if (!Resolve(module, "bb_init", Api.Init)
     || !Resolve(module, "bb_status_text", Api.StatusText)
     || !Resolve(module, "bb_mnemonic_new", Api.MnemonicNew)
     || !Resolve(module, "bb_mnemonic_validate", Api.MnemonicValidate)
     || !Resolve(module, "bb_identity_open", Api.IdentityOpen)
     || !Resolve(module, "bb_identity_free", Api.IdentityFree)) {
        FreeLibrary(module);
        FLastError = L"bbcore.dll does not expose the required C ABI.";
        return false;
    }

    const bb_status initialized = Api.Init();
    if (initialized != BB_OK) {
        FLastError = StatusMessage(initialized);
        FreeLibrary(module);
        return false;
    }
    FModule = module;
    return true;
}

bool TCoreBridge::Unlock(const UnicodeString &mnemonic)
{
    Lock();
    if (!EnsureLoaded()) return false;

    UTF8String utf8(mnemonic.Trim());
    bb_status status = Api.MnemonicValidate(utf8.c_str());
    if (status == BB_OK)
        status = Api.IdentityOpen(utf8.c_str(), "", 0, &FIdentity);

    if (utf8.Length() != 0) SecureZeroMemory(&utf8[1], utf8.Length());
    if (status != BB_OK) {
        FIdentity = nullptr;
        FLastError = StatusMessage(status);
        return false;
    }
    FLastError = L"";
    return true;
}

bool TCoreBridge::GenerateMnemonic(UnicodeString &mnemonic)
{
    mnemonic = L"";
    if (!EnsureLoaded()) return false;

    char buffer[256] = {};
    size_t length = 0;
    const bb_status status = Api.MnemonicNew(24, buffer, sizeof buffer, &length);
    if (status != BB_OK) {
        FLastError = StatusMessage(status);
        SecureZeroMemory(buffer, sizeof buffer);
        return false;
    }
    mnemonic = UnicodeString(UTF8String(buffer));
    SecureZeroMemory(buffer, sizeof buffer);
    FLastError = L"";
    return true;
}

void TCoreBridge::Lock()
{
    if (FIdentity != nullptr && Api.IdentityFree != nullptr)
        Api.IdentityFree(FIdentity);
    FIdentity = nullptr;
}
