add_executable(bbcore_tests
    main.cpp
    test_aead.cpp
    test_aead_vectors.cpp
    test_base32.cpp
    test_bip39.cpp
    test_bip39_vectors.cpp
    test_blake3.cpp
    test_hybrid_kem.cpp
    test_identity.cpp
    test_key_schedule.cpp
    test_merkle.cpp
    test_metadata.cpp
    test_object_name.cpp
    test_reed_solomon.cpp
    test_splitter.cpp
    test_stripe_builder.cpp
    test_kem.cpp
    test_shake.cpp
    test_state.cpp
    test_x25519.cpp
)

# Линкуем объекты, а не DLL: тестам нужны внутренние C++ классы, которых нет
# в экспортируемом C ABI.
target_link_libraries(bbcore_tests PRIVATE bbcore_objs)
target_compile_definitions(bbcore_tests PRIVATE BBCORE_STATIC)

target_include_directories(bbcore_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
    target_compile_options(bbcore_tests PRIVATE /W4)
else()
    target_compile_options(bbcore_tests PRIVATE -Wall -Wextra)
endif()

add_test(NAME bbcore_tests COMMAND bbcore_tests)

# Public ABI smoke test: pure C, public header only, linked to the actual library target.
add_executable(bbcore_abi_tests abi_smoke.c)
target_link_libraries(bbcore_abi_tests PRIVATE bbcore)

if(MSVC)
    target_compile_options(bbcore_abi_tests PRIVATE /W4)
else()
    target_compile_options(bbcore_abi_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32 AND BBCORE_SHARED)
    add_custom_command(TARGET bbcore_abi_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:bbcore> $<TARGET_FILE_DIR:bbcore_abi_tests>)
endif()

add_test(NAME bbcore_abi_tests COMMAND bbcore_abi_tests)
