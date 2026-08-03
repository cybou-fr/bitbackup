#include <System.hpp>
#include <System.SysUtils.hpp>
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <sstream>
#include "AppConfig.h"

typedef BOOL (WINAPI *TCryptProtectData)(DATA_BLOB*, LPCWSTR, DATA_BLOB*, PVOID,
                                        CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
typedef BOOL (WINAPI *TCryptUnprotectData)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID,
                                          CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);

static HMODULE CryptModule()
{
    static HMODULE module = LoadLibraryW(L"crypt32.dll");
    return module;
}

static TCryptProtectData ProtectFunction()
{
    return reinterpret_cast<TCryptProtectData>(GetProcAddress(CryptModule(), "CryptProtectData"));
}

static TCryptUnprotectData UnprotectFunction()
{
    return reinterpret_cast<TCryptUnprotectData>(GetProcAddress(CryptModule(), "CryptUnprotectData"));
}

static UnicodeString ConfigPath()
{
    UnicodeString base = GetEnvironmentVariable(L"LOCALAPPDATA");
    if (base.IsEmpty()) base = ExtractFilePath(ParamStr(0));
    UnicodeString dir = IncludeTrailingPathDelimiter(base) + L"BitBackup";
    ForceDirectories(dir);
    return IncludeTrailingPathDelimiter(dir) + L"config.dat";
}

static std::string Hex(const UnicodeString &value)
{
    UTF8String bytes(value);
    static const char digits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(bytes.Length() * 2);
    for (int i = 1; i <= bytes.Length(); ++i) {
        unsigned char b = (unsigned char)bytes[i];
        out.push_back(digits[b >> 4]); out.push_back(digits[b & 15]);
    }
    return out;
}

static bool Unhex(const std::string &value, UnicodeString &out)
{
    out = L"";
    if ((value.size() & 1u) != 0) return false;
    UTF8String bytes;
    bytes.SetLength((int)value.size() / 2);
    auto digit = [](char c, unsigned char &value)->bool {
        if (c >= '0' && c <= '9') value = (unsigned char)(c - '0');
        else if (c >= 'A' && c <= 'F') value = (unsigned char)(c - 'A' + 10);
        else return false;
        return true;
    };
    for (int i = 0; i < bytes.Length(); ++i) {
        unsigned char high = 0, low = 0;
        if (!digit(value[i * 2], high) || !digit(value[i * 2 + 1], low)) return false;
        bytes[i + 1] = (char)((high << 4) | low);
    }
    out = UnicodeString(bytes);
    return true;
}

static std::vector<std::string> Parts(const std::string &line)
{
    std::vector<std::string> result; std::stringstream input(line); std::string part;
    while (std::getline(input, part, '|')) result.push_back(part);
    return result;
}

TAppConfig::TAppConfig() : HasStorage(false) {}

TAppConfig &TAppConfig::Instance()
{
    static TAppConfig value;
    return value;
}

bool TAppConfig::Save() const
{
    std::ostringstream text;
    if (HasStorage)
        text << "S|" << Hex(Storage.Type) << '|' << Hex(Storage.Name) << '|' << Hex(Storage.Location)
             << '|' << Hex(Storage.User) << '|' << Hex(Storage.Secret) << "\n";
    for (const auto &folder : Folders)
        text << "F|" << Hex(folder.Path) << '|' << Hex(folder.RootLabel) << "\n";
    std::string plain = text.str();
    DATA_BLOB input = {(DWORD)plain.size(), (BYTE*)plain.data()}, output = {};
    TCryptProtectData protect = ProtectFunction();
    if (!protect || !protect(&input, L"BitBackup configuration", nullptr, nullptr, nullptr,
                             CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        SecureZeroMemory(plain.data(), plain.size());
        return false;
    }
    const UnicodeString path = ConfigPath();
    const UnicodeString temporary = path + L".tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    bool ok = false;
    if (file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        ok = WriteFile(file, output.pbData, output.cbData, &written, nullptr)
          && written == output.cbData && FlushFileBuffers(file);
        CloseHandle(file);
    }
    LocalFree(output.pbData);
    if (ok)
        ok = MoveFileExW(temporary.c_str(), path.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    if (!ok) DeleteFileW(temporary.c_str());
    SecureZeroMemory(plain.data(), plain.size());
    return ok;
}

bool TAppConfig::Load()
{
    Clear();
    HANDLE file = CreateFileW(ConfigPath().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER fileSize = {};
    if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart <= 0
     || fileSize.QuadPart > 1024 * 1024) {
        CloseHandle(file);
        return false;
    }
    DWORD size = (DWORD)fileSize.QuadPart, read = 0;
    std::vector<BYTE> encrypted(size);
    bool ok = size > 0 && ReadFile(file, encrypted.data(), size, &read, nullptr) && read == size;
    CloseHandle(file);
    if (!ok) return false;
    DATA_BLOB input = {size, encrypted.data()}, output = {};
    TCryptUnprotectData unprotect = UnprotectFunction();
    if (!unprotect || !unprotect(&input, nullptr, nullptr, nullptr, nullptr,
                                 CRYPTPROTECT_UI_FORBIDDEN, &output)) return false;
    std::string plain((char*)output.pbData, output.cbData);
    SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData);
    bool parsedStorage = false;
    TStorageConfig parsedStorageValue;
    std::vector<TFolderConfig> parsedFolders;
    std::stringstream lines(plain); std::string line;
    while (std::getline(lines, line)) {
        auto p = Parts(line);
        if (p.size() == 6 && p[0] == "S") {
            if (parsedStorage
             || !Unhex(p[1], parsedStorageValue.Type)
             || !Unhex(p[2], parsedStorageValue.Name)
             || !Unhex(p[3], parsedStorageValue.Location)
             || !Unhex(p[4], parsedStorageValue.User)
             || !Unhex(p[5], parsedStorageValue.Secret)) {
                SecureZeroMemory(plain.data(), plain.size());
                Clear();
                return false;
            }
            parsedStorage = true;
        } else if (p.size() == 3 && p[0] == "F") {
            TFolderConfig folder;
            if (!Unhex(p[1], folder.Path) || !Unhex(p[2], folder.RootLabel)) {
                SecureZeroMemory(plain.data(), plain.size());
                Clear();
                return false;
            }
            parsedFolders.push_back(folder);
        } else if (!line.empty()) {
            SecureZeroMemory(plain.data(), plain.size());
            Clear();
            return false;
        }
    }
    HasStorage = parsedStorage;
    if (parsedStorage) Storage = parsedStorageValue;
    Folders.swap(parsedFolders);
    SecureZeroMemory(plain.data(), plain.size());
    return true;
}

void TAppConfig::Clear()
{
    HasStorage = false;
    Storage.Type = L"";
    Storage.Name = L"";
    Storage.Location = L"";
    Storage.User = L"";
    Storage.Secret = L"";
    Folders.clear();
}
