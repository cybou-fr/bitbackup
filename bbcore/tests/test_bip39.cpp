// Свойства BIP39, которые официальные векторы не покрывают: целостность
// словаря, отказы на испорченных фразах, нормализация пробелов.
//
// Официальные векторы лежат в test_bip39_vectors.cpp.

#include "Testing.h"

#include "util/Bip39.h"

#include <cstring>
#include <set>
#include <string>
#include <vector>

// Двоичный поиск в Bip39FindWord верен только на отсортированном списке.
// Дубликат тоже смертелен: две мнемоники давали бы один seed.
BB_TEST(bip39_wordlist_is_sorted_and_unique)
{
    std::set<std::string> seen;

    for (std::size_t i = 0; i < bb::kBip39WordCount; ++i) {
        const char* word = bb::Bip39Word(i);
        BB_CHECK(word != nullptr);
        if (word == nullptr) {
            return;
        }
        BB_CHECK(seen.insert(word).second);

        if (i > 0) {
            BB_CHECK(std::strcmp(bb::Bip39Word(i - 1), word) < 0);
        }
    }

    BB_CHECK_EQ(seen.size(), bb::kBip39WordCount);
    BB_CHECK(bb::Bip39Word(bb::kBip39WordCount) == nullptr);
}

BB_TEST(bip39_every_word_is_found_at_its_index)
{
    for (std::size_t i = 0; i < bb::kBip39WordCount; ++i) {
        std::uint16_t index = 0;
        BB_CHECK(bb::Bip39FindWord(bb::Bip39Word(i), index));
        BB_CHECK_EQ(static_cast<std::size_t>(index), i);
    }
}

BB_TEST(bip39_rejects_words_outside_the_list)
{
    std::uint16_t index = 0;
    BB_CHECK(!bb::Bip39FindWord("", index));
    BB_CHECK(!bb::Bip39FindWord("abandonn", index));
    BB_CHECK(!bb::Bip39FindWord("Abandon", index));   // регистр значим
    BB_CHECK(!bb::Bip39FindWord("zzzz", index));
    BB_CHECK(!bb::Bip39FindWord("aaaa", index));
}

BB_TEST(bip39_generated_mnemonics_validate_and_differ)
{
    std::string first;
    std::string second;

    BB_CHECK(bb::Bip39Generate(24, first));
    BB_CHECK(bb::Bip39Generate(24, second));

    BB_CHECK(bb::Bip39Validate(first));
    BB_CHECK(bb::Bip39Validate(second));
    BB_CHECK(first != second);

    std::string twelve;
    BB_CHECK(!bb::Bip39Generate(12, twelve));
}

// В ABI объявлены только 12 и 24 слова; всё остальное — ошибка вызывающего,
// а не молчаливое округление до ближайшей поддержанной длины.
BB_TEST(bip39_generate_rejects_unsupported_lengths)
{
    std::string mnemonic;
    BB_CHECK(!bb::Bip39Generate(0, mnemonic));
    BB_CHECK(!bb::Bip39Generate(11, mnemonic));
    BB_CHECK(!bb::Bip39Generate(12, mnemonic));
    BB_CHECK(!bb::Bip39Generate(18, mnemonic));   // читать умеем, выдавать нет
    BB_CHECK(!bb::Bip39Generate(25, mnemonic));
}

// Читаются все пять стандартных длин: фраза из чужого кошелька должна
// открываться, а не требовать перегенерации.
BB_TEST(bip39_accepts_every_standard_length)
{
    for (std::size_t entropy_len = 16; entropy_len <= 32; entropy_len += 4) {
        std::vector<std::uint8_t> entropy(entropy_len, 0x5A);

        std::string mnemonic;
        BB_CHECK(bb::Bip39FromEntropy(entropy.data(), entropy.size(), mnemonic));
        BB_CHECK(bb::Bip39Validate(mnemonic));

        std::uint8_t recovered[32];
        std::size_t  len = 0;
        BB_CHECK(bb::Bip39ToEntropy(mnemonic, recovered, sizeof recovered, &len));
        BB_CHECK_EQ(len, entropy_len);
        BB_CHECK_EQ(std::memcmp(recovered, entropy.data(), entropy_len), 0);
    }
}

BB_TEST(bip39_from_entropy_rejects_bad_lengths)
{
    std::uint8_t entropy[32] = {};
    std::string  mnemonic;

    BB_CHECK(!bb::Bip39FromEntropy(entropy, 0, mnemonic));
    BB_CHECK(!bb::Bip39FromEntropy(entropy, 15, mnemonic));
    BB_CHECK(!bb::Bip39FromEntropy(entropy, 17, mnemonic));
    BB_CHECK(!bb::Bip39FromEntropy(entropy, 33, mnemonic));
    BB_CHECK(!bb::Bip39FromEntropy(nullptr, 16, mnemonic));
}

// Ради этого контрольная сумма и существует: опечатка в одном слове обязана
// быть отвергнута, а не открыть пустой архив под чужой identity.
BB_TEST(bip39_rejects_corrupted_mnemonics)
{
    const char* valid =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    BB_CHECK(bb::Bip39Validate(valid));

    // Последнее слово несёт контрольную сумму.
    BB_CHECK(!bb::Bip39Validate(
        "legal winner thank year wave sausage worth useful legal winner thank zoo"));

    // Слово вне словаря.
    BB_CHECK(!bb::Bip39Validate(
        "legal winner thank year wave sausage worth useful legal winner thank banana2"));

    // Перестановка двух слов ломает и биты, и контрольную сумму.
    BB_CHECK(!bb::Bip39Validate(
        "winner legal thank year wave sausage worth useful legal winner thank yellow"));

    // Не та длина.
    BB_CHECK(!bb::Bip39Validate(""));
    BB_CHECK(!bb::Bip39Validate("abandon"));
    BB_CHECK(!bb::Bip39Validate(
        "legal winner thank year wave sausage worth useful legal winner thank"));

    // Регистр не приводится: BIP39 определён на строчных словах.
    BB_CHECK(!bb::Bip39Validate(
        "Legal winner thank year wave sausage worth useful legal winner thank yellow"));
}

// Пользователь копирует фразу из текста, и в ней оказываются переводы строк и
// двойные пробелы. Это не должно быть поводом отказать.
BB_TEST(bip39_tolerates_surrounding_whitespace)
{
    const char* canonical =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const char* messy =
        "  legal   winner\tthank year\nwave sausage worth useful legal winner thank yellow \r\n";

    BB_CHECK(bb::Bip39Validate(messy));
    BB_CHECK_STR(bb::Bip39Normalize(messy).c_str(), canonical);

    // Из чего следует главное: seed от небрежно вставленной фразы тот же.
    bb::Bip39Seed clean{};
    bb::Bip39Seed dirty{};
    BB_CHECK(bb::Bip39DeriveSeed(canonical, "", clean));
    BB_CHECK(bb::Bip39DeriveSeed(messy, "", dirty));
    BB_CHECK_EQ(std::memcmp(clean.data(), dirty.data(), clean.size()), 0);
}

// Парольная фраза — второй фактор: та же мнемоника с другой фразой это другой
// архив, а не ошибка. Пустая фраза и её отсутствие эквивалентны.
BB_TEST(bip39_passphrase_changes_the_seed)
{
    const char* mnemonic =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    bb::Bip39Seed none{};
    bb::Bip39Seed with{};
    BB_CHECK(bb::Bip39DeriveSeed(mnemonic, "", none));
    BB_CHECK(bb::Bip39DeriveSeed(mnemonic, "TREZOR", with));

    BB_CHECK(std::memcmp(none.data(), with.data(), none.size()) != 0);
}

BB_TEST(bip39_to_entropy_reports_size_for_small_buffer)
{
    const char* mnemonic =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    std::uint8_t small[8];
    std::size_t  len = 0;
    BB_CHECK(!bb::Bip39ToEntropy(mnemonic, small, sizeof small, &len));
    BB_CHECK_EQ(len, bb::kBip39Entropy12);
}
