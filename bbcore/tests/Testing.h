// Минимальный тестовый раннер. Отдельного фреймворка пока не берём: у ядра
// нет других зависимостей, и заводить их ради assert-макросов не хочется.
//
// Использование:
//
//     BB_TEST(name) { BB_CHECK(cond); BB_CHECK_EQ(a, b); }
//     int main() { return bb::test::RunAll(); }

#ifndef BBCORE_TESTS_TESTING_H
#define BBCORE_TESTS_TESTING_H

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace bb {
namespace test {

struct Case {
    const char* name;
    void (*fn)(int& failures);
};

inline std::vector<Case>& Registry()
{
    static std::vector<Case> registry;
    return registry;
}

struct Registrar {
    Registrar(const char* name, void (*fn)(int&))
    {
        Registry().push_back(Case{name, fn});
    }
};

inline int RunAll()
{
    int failed_cases = 0;

    for (const Case& c : Registry()) {
        int failures = 0;
        c.fn(failures);
        if (failures == 0) {
            std::printf("[  ok  ] %s\n", c.name);
        } else {
            std::printf("[ FAIL ] %s (%d check(s))\n", c.name, failures);
            ++failed_cases;
        }
    }

    std::printf("\n%zu case(s), %d failed\n", Registry().size(), failed_cases);
    return failed_cases == 0 ? 0 : 1;
}

/// Печать байтового буфера для диагностики.
inline std::string Hex(const unsigned char* data, std::size_t len)
{
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

}  // namespace test
}  // namespace bb

#define BB_TEST(name)                                                        \
    static void bb_test_##name(int& bb_failures);                            \
    static ::bb::test::Registrar bb_reg_##name(#name, &bb_test_##name);      \
    static void bb_test_##name([[maybe_unused]] int& bb_failures)

#define BB_CHECK(cond)                                                       \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::printf("    %s:%d: expected %s\n",                          \
                        __FILE__, __LINE__, #cond);                          \
            ++bb_failures;                                                   \
        }                                                                    \
    } while (0)

#define BB_CHECK_EQ(actual, expected)                                        \
    do {                                                                     \
        if (!((actual) == (expected))) {                                     \
            std::printf("    %s:%d: %s != %s\n",                             \
                        __FILE__, __LINE__, #actual, #expected);             \
            ++bb_failures;                                                   \
        }                                                                    \
    } while (0)

#define BB_CHECK_STR(actual, expected)                                       \
    do {                                                                     \
        if (std::strcmp((actual), (expected)) != 0) {                        \
            std::printf("    %s:%d: got \"%s\", want \"%s\"\n",              \
                        __FILE__, __LINE__, (actual), (expected));           \
            ++bb_failures;                                                   \
        }                                                                    \
    } while (0)

#endif  // BBCORE_TESTS_TESTING_H
