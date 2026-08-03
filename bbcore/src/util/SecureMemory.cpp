#include "bbcore/bbcore.h"

#include <cstring>

#if defined(_WIN32)
#  include <windows.h>
#else
#  include <sys/mman.h>
#endif

BB_API void BB_CALL bb_secure_zero(void* data, size_t len)
{
    if (data == nullptr || len == 0) {
        return;
    }

#if defined(_WIN32)
    SecureZeroMemory(data, len);
#else
    // volatile-указатель не даёт компилятору выбросить запись как мёртвую.
    volatile unsigned char* p = static_cast<volatile unsigned char*>(data);
    while (len-- != 0) {
        *p++ = 0;
    }
#endif
}

BB_API bb_status BB_CALL bb_secure_lock(void* data, size_t len)
{
    if (data == nullptr || len == 0) {
        return BB_ERR_INVALID_ARG;
    }

#if defined(_WIN32)
    // VirtualLock ограничен рабочим набором процесса. Исчерпание лимита —
    // не мелочь: без блокировки ключи могут уйти в pagefile, а вся модель
    // угроз строится на том, что на диске ничего нет. Ошибку обязан
    // обработать вызывающий.
    if (VirtualLock(data, len) == 0) {
        return BB_ERR_UNSUPPORTED;
    }
    return BB_OK;
#else
    return (mlock(data, len) == 0) ? BB_OK : BB_ERR_UNSUPPORTED;
#endif
}

BB_API void BB_CALL bb_secure_unlock(void* data, size_t len)
{
    if (data == nullptr || len == 0) {
        return;
    }

    bb_secure_zero(data, len);

#if defined(_WIN32)
    VirtualUnlock(data, len);
#else
    munlock(data, len);
#endif
}
