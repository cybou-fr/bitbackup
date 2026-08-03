// Внутреннее представление bb_identity. Заголовок нужен потому, что дескриптор
// создаётся в api/Identity.cpp, а разбирают его и другие точки входа C ABI.

#ifndef BBCORE_API_IDENTITYHANDLE_H
#define BBCORE_API_IDENTITYHANDLE_H

#include "identity/Identity.h"

struct bb_identity {
    bb::Identity impl;
};

#endif  // BBCORE_API_IDENTITYHANDLE_H
