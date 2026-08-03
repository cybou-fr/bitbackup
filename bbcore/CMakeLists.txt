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
    src/util/Base32.cpp
    src/util/SecureMemory.cpp
)

if(BBCORE_SHARED)
    add_library(bbcore SHARED ${BBCORE_SOURCES})
else()
    add_library(bbcore STATIC ${BBCORE_SOURCES})
    target_compile_definitions(bbcore PUBLIC BBCORE_STATIC)
endif()

add_library(bbcore::bbcore ALIAS bbcore)

target_compile_definitions(bbcore PRIVATE BBCORE_BUILD)

target_include_directories(bbcore
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

set_target_properties(bbcore PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME bbcore)

# ---------------------------------------------------------------------------
# Предупреждения
# ---------------------------------------------------------------------------

if(MSVC)
    target_compile_options(bbcore PRIVATE /W4 /permissive-)
else()
    target_compile_options(bbcore PRIVATE
        -Wall -Wextra -Wpedantic
        -Wconversion -Wsign-conversion
        -Wshadow -Wcast-qual)
endif()

# ---------------------------------------------------------------------------
# Зависимости
#
# Пока не подключены. Порядок добавления по мере реализации модулей:
#   OpenSSL >= 3.5  ML-KEM-1024, ML-DSA-87, X25519, SHAKE256, AES-256-GCM-SIV
#   BLAKE3          https://github.com/BLAKE3-team/BLAKE3  (c/)
#   zstd            потоковое сжатие
#   Reed-Solomon    собственная реализация над GF(2^8), матрица Коши
#
# liboqs намеренно не берём: OpenSSL 3.5 даёт ML-KEM и ML-DSA штатно, включая
# детерминированную генерацию ключей из seed (64 байта для ML-KEM, 32 для ML-DSA),
# что и нужно для вывода identity из мнемоники.
#
# AES-256-GCM-SIV есть только в default provider OpenSSL, но не в FIPS provider,
# поэтому полный FIPS mode продукт не заявляет. См. docs/ARCHITECTURE.md §30.
#
# Подключать через FetchContent с зафиксированными тегами и хешами:
# ни одна зависимость не тянется из системы, чтобы сборка была
# воспроизводимой на машине разработчика и в CI.
# ---------------------------------------------------------------------------

# include(cmake/Dependencies.cmake)

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
