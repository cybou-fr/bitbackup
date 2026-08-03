// BIP39 — единственный вход в систему. Мнемоника это и есть весь секрет
// пользователя: на устройстве не хранится ничего (§22), поэтому из этих слов
// выводится всё остальное — identity, ключи файлов, имена объектов.
//
// Реализуется только английский словарь. Остальные списки BIP39 существуют, но
// каждый добавленный язык это ещё 2048 слов в бинарнике и ещё один способ для
// пользователя записать фразу так, что её потом не примет другой клиент.
//
// Нормализация. Спецификация требует NFKD и мнемоники, и парольной фразы.
// Английские слова целиком ASCII, для них NFKD тождественна, поэтому мнемоника
// нормализуется только по пробелам. Парольная фраза передаётся в PBKDF2 как
// есть, байтами UTF-8: полноценный NFKD потребовал бы ICU. Пока это ограничение
// (см. Bip39DeriveSeed) — не-ASCII парольная фраза, набранная в другой форме
// юникода, даст другой seed.

#ifndef BBCORE_UTIL_BIP39_H
#define BBCORE_UTIL_BIP39_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace bb {

inline constexpr std::size_t kBip39WordCount   = 2048;
inline constexpr std::size_t kBip39SeedLen     = 64;

/// Асимметрия намеренная: генерируются только 12 и 24 слова, принимаются все
/// пять стандартных длин BIP39 (12, 15, 18, 21, 24).
///
/// Предлагать пользователю пять вариантов в диалоге — лишний способ ослабить
/// фразу без всякой выгоды. Но отказаться прочитать корректную фразу на 18 слов,
/// принесённую из другого кошелька, значит потребовать её перегенерации, то есть
/// потерять доступ к чужому архиву на ровном месте.
inline constexpr std::size_t kBip39Words12     = 12;
inline constexpr std::size_t kBip39Words24     = 24;
inline constexpr std::size_t kBip39Entropy12   = 16;
inline constexpr std::size_t kBip39Entropy24   = 32;

inline constexpr std::size_t kBip39EntropyMin  = 16;
inline constexpr std::size_t kBip39EntropyMax  = 32;
inline constexpr std::size_t kBip39EntropyStep = 4;

using Bip39Seed = std::array<std::uint8_t, kBip39SeedLen>;

/// Слово по индексу или nullptr, если индекс за пределами словаря.
const char* Bip39Word(std::size_t index);

/// Индекс слова. Двоичный поиск по отсортированному словарю.
bool Bip39FindWord(std::string_view word, std::uint16_t& out_index);

/// Мнемоника из готовой энтропии. len — от 16 до 32 байт с шагом 4.
bool Bip39FromEntropy(const std::uint8_t* entropy, std::size_t len,
                      std::string& out_mnemonic);

/// Мнемоника из системного CSPRNG. words — 12 или 24.
bool Bip39Generate(unsigned words, std::string& out_mnemonic);

/// Словарь и контрольная сумма. Принимает 12, 15, 18, 21 и 24 слова. Лишние
/// пробелы допускаются, регистр — нет.
bool Bip39Validate(std::string_view mnemonic);

/// Обратное преобразование: мнемоника → энтропия. Заодно проверяет фразу.
/// out_len выставляется и при слишком маленьком буфере.
bool Bip39ToEntropy(std::string_view mnemonic,
                    std::uint8_t* out_entropy, std::size_t cap,
                    std::size_t* out_len);

/// seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" || passphrase, 2048, 64).
///
/// Фраза при этом НЕ проверяется на контрольную сумму: BIP39 определяет seed
/// для любой строки, и проверка — отдельное решение вызывающего.
bool Bip39DeriveSeed(std::string_view mnemonic, std::string_view passphrase,
                     Bip39Seed& out_seed);

/// Приведение к канонической форме: слова через один пробел, без краёв.
std::string Bip39Normalize(std::string_view mnemonic);

}  // namespace bb

#endif  // BBCORE_UTIL_BIP39_H
