add_executable(bbcore_tests
    main.cpp
    test_aead.cpp
    test_aead_vectors.cpp
    test_base32.cpp
    test_bip39.cpp
    test_bip39_vectors.cpp
    test_blake3.cpp
    test_identity.cpp
    test_object_name.cpp
    test_kem.cpp
    test_shake.cpp
    test_x25519.cpp
)

# Линкуем объекты, а не DLL: тестам нужны внутренние C++ классы, которых нет
# в экспортируемом C ABI.
target_link_libraries(bbcore_tests PRIVATE bbcore_objs)

target_include_directories(bbcore_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
    target_compile_options(bbcore_tests PRIVATE /W4)
else()
    target_compile_options(bbcore_tests PRIVATE -Wall -Wextra)
endif()

add_test(NAME bbcore_tests COMMAND bbcore_tests)
