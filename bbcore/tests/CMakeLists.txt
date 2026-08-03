add_executable(bbcore_tests
    main.cpp
    test_base32.cpp
    test_object_name.cpp
)

target_link_libraries(bbcore_tests PRIVATE bbcore)

target_include_directories(bbcore_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
    target_compile_options(bbcore_tests PRIVATE /W4)
else()
    target_compile_options(bbcore_tests PRIVATE -Wall -Wextra)
endif()

add_test(NAME bbcore_tests COMMAND bbcore_tests)

# DLL должна лежать рядом с тестовым бинарником на Windows.
if(WIN32 AND BBCORE_SHARED)
    add_custom_command(TARGET bbcore_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:bbcore> $<TARGET_FILE_DIR:bbcore_tests>)
endif()
