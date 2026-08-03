cmake_minimum_required(VERSION 3.20)

project(bbcore
    VERSION 0.1.0
    DESCRIPTION "BitBackup core library — bbk/1 container format"
    LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# Опции
# ---------------------------------------------------------------------------

option(BBCORE_BUILD_TESTS  "Собирать тесты"          ON)
option(BBCORE_BUILD_CLI    "Собирать утилиту bbk"    ON)
option(BBCORE_SHARED       "Собирать DLL/so"         ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------------------
# Исходники
# ---------------------------------------------------------------------------

set(BBCORE_SOURCES
    src/api/Status.cpp
    src/api/Names.cpp
    src/api/Identity.cpp
    src/crypto/Aead.cpp
    src/crypto/Hash.cpp
    src/crypto/HybridKem.cpp
    src/crypto/Kem.cpp
    src/crypto/Shake.cpp
    src/crypto/X25519.cpp
    src/identity/Identity.cpp
    src/util/Base32.cpp
    src/util/Bip39.cpp
    src/util/Bip39Wordlist.cpp
    src/util/SecureMemory.cpp
)

# Объектная библиотека, а не прямая сборка в SHARED: у DLL скрыта видимость и
# наружу торчит только C ABI, поэтому тесты не смогли бы дотянуться до
# внутренних C++ классов вроде bb::MlKemKeyPair. Тесты линкуют объекты
# напрямую, релизная DLL собирается из тех же объектов.
add_library(bbcore_objs OBJECT ${BBCORE_SOURCES})

target_compile_definitions(bbcore_objs PRIVATE BBCORE_BUILD)

target_include_directories(bbcore_objs
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

if(BBCORE_SHARED)
    add_library(bbcore SHARED)
else()
    add_library(bbcore STATIC)
    target_compile_definitions(bbcore PUBLIC BBCORE_STATIC)
endif()

add_library(bbcore::bbcore ALIAS bbcore)

target_link_libraries(bbcore PRIVATE bbcore_objs)

target_include_directories(bbcore
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

set_target_properties(bbcore PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME bbcore
    LINKER_LANGUAGE CXX)

# ---------------------------------------------------------------------------
# Предупреждения
# ---------------------------------------------------------------------------

if(MSVC)
    target_compile_options(bbcore_objs PRIVATE /W4 /permissive-)
else()
    target_compile_options(bbcore_objs PRIVATE
        -Wall -Wextra -Wpedantic
        -Wconversion -Wsign-conversion
        -Wshadow -Wcast-qual)
endif()

# ---------------------------------------------------------------------------
# Зависимости
#
# Версии пинятся в vcpkg.json, сборка идёт через пресеты из
# CMakePresets.json — им нужна переменная окружения VCPKG_ROOT.
#
# OpenSSL >= 3.5 закрывает весь криптографический набор bbk/1:
#   ML-KEM-1024, ML-DSA-87, X25519, SHAKE256, AES-256-GCM-SIV.
#
# liboqs намеренно не берём: OpenSSL даёт ML-KEM и ML-DSA штатно, включая
# детерминированную генерацию ключей из seed (64 байта для ML-KEM, 32 для
# ML-DSA), что и нужно для вывода identity из мнемоники.
#
# AES-256-GCM-SIV есть только в default provider OpenSSL, но не в FIPS
# provider, поэтому полный FIPS mode продукт не заявляет. См. §30.
#
# BLAKE3 идёт отдельным портом: в OpenSSL его нет, а формат опирается на него
# в content_hash, file_id, Merkle-дереве и identity_id (§4, §6, §11, §13).
#
# Ещё предстоит добавить: zstd. Reed-Solomon пишется свой.
# ---------------------------------------------------------------------------

find_package(OpenSSL 3.5 REQUIRED)
find_package(blake3 CONFIG REQUIRED)

# PUBLIC на объектной библиотеке: и DLL, и тесты линкуются с одним OpenSSL.
target_link_libraries(bbcore_objs PUBLIC OpenSSL::Crypto BLAKE3::blake3)

# Проверяем не только версию, но и наличие самого алгоритма: собраться с
# OpenSSL без ML-KEM и узнать об этом в рантайме — худший из вариантов.
include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_LIBRARIES OpenSSL::Crypto)
check_cxx_source_compiles("
    #include <openssl/evp.h>
    int main() {
        EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_from_name(0, \"ML-KEM-1024\", 0);
        return c ? 0 : 1;
    }" BBCORE_HAVE_MLKEM)
unset(CMAKE_REQUIRED_LIBRARIES)

if(NOT BBCORE_HAVE_MLKEM)
    message(FATAL_ERROR
        "OpenSSL ${OPENSSL_VERSION} does not expose ML-KEM-1024. "
        "bbk/1 requires it; build against OpenSSL 3.5 or newer.")
endif()

message(STATUS "bbcore: OpenSSL ${OPENSSL_VERSION}, ML-KEM-1024 available")

# ---------------------------------------------------------------------------
# Тесты
# ---------------------------------------------------------------------------

if(BBCORE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(BBCORE_BUILD_CLI)
    # add_subdirectory(tools/bbk)
endif()

# ---------------------------------------------------------------------------
# Установка
# ---------------------------------------------------------------------------

include(GNUInstallDirs)

install(TARGETS bbcore
    EXPORT bbcoreTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
