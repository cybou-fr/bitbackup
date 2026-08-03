#include <System.hpp>
#include <System.SysUtils.hpp>
#include <windows.h>
#include <wincrypt.h>

#include <array>
#include <climits>
#include <cstring>
#include <utility>
#include <vector>

#include "AppConfig.h"
#include "CoreBridge.h"

typedef BOOL (WINAPI *TCryptUnprotectData)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID,
                                          CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);

namespace {

struct Slice {
    const unsigned char *Data;
    std::size_t Length;
};

static HMODULE CryptModule()
{
    static HMODULE module = LoadLibraryW(L"crypt32.dll");
    return module;
}

static TCryptUnprotectData UnprotectFunction()
{
    return reinterpret_cast<TCryptUnprotectData>(GetProcAddress(CryptModule(), "CryptUnprotectData"));
}

static UnicodeString ConfigDirectory()
{
    UnicodeString base = GetEnvironmentVariable(L"LOCALAPPDATA");
    if (base.IsEmpty()) base = ExtractFilePath(ParamStr(0));
    UnicodeString dir = IncludeTrailingPathDelimiter(base) + L"BitBackup";
    ForceDirectories(dir);
    return IncludeTrailingPathDelimiter(dir);
}

static UnicodeString ConfigPath()
{
    UnicodeString identityId;
    if (!TCoreBridge::Instance().IdentityIdText(identityId)) return L"";
    return ConfigDirectory() + L"config-" + identityId + L".dat";
}

static UnicodeString LegacyConfigPath()
{
    return ConfigDirectory() + L"config.dat";
}

static void WipeBytes(std::vector<unsigned char> &value)
{
    if (!value.empty()) SecureZeroMemory(value.data(), value.size());
    value.clear();
}

static void WipeString(UnicodeString &value)
{
    if (!value.IsEmpty()) {
        System::UniqueString(value);
        SecureZeroMemory(&value[1], value.Length() * sizeof(System::WideChar));
    }
    value = L"";
}

static void WipeStorage(TStorageConfig &value)
{
    WipeString(value.Type);
    WipeString(value.Name);
    WipeString(value.Location);
    WipeString(value.User);
    WipeString(value.Secret);
}

static void WipeFolders(std::vector<TFolderConfig> &folders)
{
    for (auto &folder : folders) {
        WipeString(folder.Path);
        WipeString(folder.RootLabel);
    }
    folders.clear();
}

static void AppendAscii(std::vector<unsigned char> &out, const char *value)
{
    const std::size_t length = std::strlen(value);
    out.insert(out.end(), value, value + length);
}

static void AppendHex(std::vector<unsigned char> &out, const UnicodeString &value)
{
    UTF8String bytes(value);
    static const unsigned char digits[] = "0123456789ABCDEF";
    out.reserve(out.size() + static_cast<std::size_t>(bytes.Length()) * 2);
    for (int i = 1; i <= bytes.Length(); ++i) {
        const unsigned char byte = static_cast<unsigned char>(bytes[i]);
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 15]);
    }
    if (bytes.Length() != 0) SecureZeroMemory(&bytes[1], bytes.Length());
}

static bool DecodeHex(const Slice &value, UnicodeString &out)
{
    WipeString(out);
    if ((value.Length & 1u) != 0 || value.Length / 2 > static_cast<std::size_t>(INT_MAX))
        return false;

    UTF8String bytes;
    bytes.SetLength(static_cast<int>(value.Length / 2));
    auto digit = [](unsigned char character, unsigned char &decoded)->bool {
        if (character >= '0' && character <= '9') decoded = character - '0';
        else if (character >= 'A' && character <= 'F') decoded = character - 'A' + 10;
        else return false;
        return true;
    };
    for (int i = 0; i < bytes.Length(); ++i) {
        unsigned char high = 0, low = 0;
        if (!digit(value.Data[i * 2], high) || !digit(value.Data[i * 2 + 1], low)) {
            if (bytes.Length() != 0) SecureZeroMemory(&bytes[1], bytes.Length());
            return false;
        }
        bytes[i + 1] = static_cast<char>((high << 4) | low);
    }
    out = UnicodeString(bytes);
    if (bytes.Length() != 0) SecureZeroMemory(&bytes[1], bytes.Length());
    return true;
}

static bool SplitLine(const unsigned char *data, std::size_t length,
                      Slice *parts, std::size_t capacity, std::size_t &count)
{
    count = 0;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= length; ++i) {
        if (i != length && data[i] != '|') continue;
        if (count == capacity) return false;
        parts[count++] = {data + start, i - start};
        start = i + 1;
    }
    return true;
}

}  // namespace

TAppConfig::TAppConfig() : HasStorage(false) {}

TAppConfig::~TAppConfig()
{
    Clear();
}

TAppConfig &TAppConfig::Instance()
{
    static TAppConfig value;
    return value;
}

bool TAppConfig::Save() const
{
    std::vector<unsigned char> plain;
    if (HasStorage) {
        AppendAscii(plain, "S|"); AppendHex(plain, Storage.Type);
        AppendAscii(plain, "|");  AppendHex(plain, Storage.Name);
        AppendAscii(plain, "|");  AppendHex(plain, Storage.Location);
        AppendAscii(plain, "|");  AppendHex(plain, Storage.User);
        AppendAscii(plain, "|");  AppendHex(plain, Storage.Secret);
        AppendAscii(plain, "\n");
    }
    for (const auto &folder : Folders) {
        AppendAscii(plain, "F|"); AppendHex(plain, folder.Path);
        AppendAscii(plain, "|");  AppendHex(plain, folder.RootLabel);
        AppendAscii(plain, "\n");
    }

    std::vector<unsigned char> sealed;
    if (!TCoreBridge::Instance().SealState(plain.data(), plain.size(), sealed)) {
        WipeBytes(plain);
        return false;
    }
    WipeBytes(plain);

    const UnicodeString path = ConfigPath();
    if (path.IsEmpty()) {
        WipeBytes(sealed);
        return false;
    }
    const UnicodeString temporary = path + L".tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    bool ok = false;
    if (file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        ok = sealed.size() <= MAXDWORD
          && WriteFile(file, sealed.data(), static_cast<DWORD>(sealed.size()), &written, nullptr)
          && written == sealed.size() && FlushFileBuffers(file);
        CloseHandle(file);
    }
    WipeBytes(sealed);
    if (ok)
        ok = MoveFileExW(temporary.c_str(), path.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    if (!ok) DeleteFileW(temporary.c_str());
    return ok;
}

bool TAppConfig::Load()
{
    Clear();
    const UnicodeString primaryPath = ConfigPath();
    if (primaryPath.IsEmpty()) return false;
    UnicodeString readPath = primaryPath;
    bool migratedPath = false;
    if (GetFileAttributesW(readPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        readPath = LegacyConfigPath();
        migratedPath = true;
    }
    HANDLE file = CreateFileW(readPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER fileSize = {};
    if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart <= 0
     || fileSize.QuadPart > 1024 * 1024) {
        CloseHandle(file);
        return false;
    }
    const DWORD size = static_cast<DWORD>(fileSize.QuadPart);
    DWORD read = 0;
    std::vector<unsigned char> encrypted(size);
    const bool readOk = ReadFile(file, encrypted.data(), size, &read, nullptr) && read == size;
    CloseHandle(file);
    if (!readOk) {
        WipeBytes(encrypted);
        return false;
    }

    const bool identityState = size >= 6 && std::memcmp(encrypted.data(), "bbk1st", 6) == 0;
    bool migrated = migratedPath;
    std::vector<unsigned char> opened;
    if (identityState) {
        if (!TCoreBridge::Instance().OpenState(encrypted.data(), encrypted.size(), opened)) {
            WipeBytes(encrypted);
            return false;
        }
    } else {
        DATA_BLOB input = {size, encrypted.data()}, output = {};
        TCryptUnprotectData unprotect = UnprotectFunction();
        if (!unprotect || !unprotect(&input, nullptr, nullptr, nullptr, nullptr,
                                     CRYPTPROTECT_UI_FORBIDDEN, &output)) {
            WipeBytes(encrypted);
            return false;
        }
        opened.assign(output.pbData, output.pbData + output.cbData);
        SecureZeroMemory(output.pbData, output.cbData);
        LocalFree(output.pbData);
        migrated = true;
    }
    WipeBytes(encrypted);

    bool parsedStorage = false;
    TStorageConfig parsedStorageValue;
    std::vector<TFolderConfig> parsedFolders;
    bool valid = true;
    std::size_t lineStart = 0;
    while (valid && lineStart < opened.size()) {
        std::size_t lineEnd = lineStart;
        while (lineEnd < opened.size() && opened[lineEnd] != '\n') ++lineEnd;
        if (lineEnd == lineStart) {
            valid = false;
            break;
        }
        std::array<Slice, 6> parts{};
        std::size_t partCount = 0;
        valid = SplitLine(opened.data() + lineStart, lineEnd - lineStart,
                          parts.data(), parts.size(), partCount);
        if (valid && partCount == 6 && parts[0].Length == 1 && parts[0].Data[0] == 'S') {
            valid = !parsedStorage
                 && DecodeHex(parts[1], parsedStorageValue.Type)
                 && DecodeHex(parts[2], parsedStorageValue.Name)
                 && DecodeHex(parts[3], parsedStorageValue.Location)
                 && DecodeHex(parts[4], parsedStorageValue.User)
                 && DecodeHex(parts[5], parsedStorageValue.Secret);
            parsedStorage = valid;
        } else if (valid && partCount == 3 && parts[0].Length == 1 && parts[0].Data[0] == 'F') {
            TFolderConfig folder;
            valid = DecodeHex(parts[1], folder.Path) && DecodeHex(parts[2], folder.RootLabel);
            if (valid) parsedFolders.push_back(std::move(folder));
            else {
                WipeString(folder.Path);
                WipeString(folder.RootLabel);
            }
        } else {
            valid = false;
        }
        lineStart = lineEnd + 1;
    }
    WipeBytes(opened);

    if (!valid) {
        WipeStorage(parsedStorageValue);
        WipeFolders(parsedFolders);
        Clear();
        return false;
    }
    HasStorage = parsedStorage;
    if (parsedStorage) Storage = std::move(parsedStorageValue);
    Folders.swap(parsedFolders);
    if (migrated) {
        if (!Save()) {
            Clear();
            return false;
        }
        if (migratedPath) DeleteFileW(readPath.c_str());
    }
    return true;
}

void TAppConfig::Clear()
{
    HasStorage = false;
    WipeStorage(Storage);
    WipeFolders(Folders);
}
