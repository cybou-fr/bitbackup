#ifndef AppConfigH
#define AppConfigH

#include <System.hpp>
#include <vector>

struct TStorageConfig
{
    UnicodeString Type, Name, Location, User, Secret;
};

struct TFolderConfig
{
    UnicodeString Path, RootLabel;
};

class TAppConfig
{
private:
    TAppConfig();
public:
    bool HasStorage;
    TStorageConfig Storage;
    std::vector<TFolderConfig> Folders;
    static TAppConfig &Instance();
    bool Load();
    bool Save() const;
    void Clear();
};

#endif
