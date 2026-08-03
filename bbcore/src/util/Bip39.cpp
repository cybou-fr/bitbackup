#include "util/Bip39.h"

#include "bbcore/bbcore.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <vector>

namespace bb {
namespace {

constexpr std::size_t kBitsPerWord = 11;

bool IsSpace(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

std::vector<std::string_view> SplitWords(std::string_view text)
{
    std::vector<std::string_view> words;
    std::size_t                   i = 0;

    while (i < text.size()) {
        while (i < text.size() && IsSpace(text[i])) {
            ++i;
        }
        const std::size_t start = i;
        while (i < text.size() && !IsSpace(text[i])) {
            ++i;
        }
        if (i > start) {
            words.push_back(text.substr(start, i - start));
        }
    }
    return words;
}

bool EntropyLenIsSupported(std::size_t len)
{
    return len >= kBip39EntropyMin && len <= kBip39EntropyMax
        && len % kBip39EntropyStep == 0;
}

/// Обратное соответствие: 12→16, 15→20, 18→24, 21→28, 24→32 байта.
/// Слов = (ENT + ENT/32) / 11, откуда ENT = words * 11 * 32 / 33 / 8.
bool EntropyLenForWords(std::size_t words, std::size_t& out_len)
{
    if (words < 12 || words > 24 || words % 3 != 0) {
        return false;
    }
    out_len = words * kBitsPerWord * 32 / 33 / 8;
    return EntropyLenIsSupported(out_len);
}

/// Первые cs_bits бит SHA-256 энтропии — контрольная сумма BIP39.
std::uint8_t ChecksumByte(const std::uint8_t* entropy, std::size_t len, std::size_t cs_bits)
{
    std::uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(entropy, len, digest);

    const std::uint8_t mask = static_cast<std::uint8_t>(0xFFu << (8 - cs_bits));
    const std::uint8_t cs   = static_cast<std::uint8_t>(digest[0] & mask);

    bb_secure_zero(digest, sizeof digest);
    return cs;
}

}  // namespace

std::string Bip39Normalize(std::string_view mnemonic)
{
    const std::vector<std::string_view> words = SplitWords(mnemonic);

    std::string out;
    for (std::size_t i = 0; i < words.size(); ++i) {
        if (i != 0) {
            out.push_back(' ');
        }
        out.append(words[i].data(), words[i].size());
    }
    return out;
}

bool Bip39FromEntropy(const std::uint8_t* entropy, std::size_t len,
                      std::string& out_mnemonic)
{
    if (entropy == nullptr || !EntropyLenIsSupported(len)) {
        return false;
    }

    const std::size_t cs_bits    = len * 8 / 32;
    const std::size_t word_count = (len * 8 + cs_bits) / kBitsPerWord;

    // Энтропия и контрольная сумма подряд: контрольных бит всегда 4 или 8,
    // поэтому одного добавочного байта достаточно.
    std::vector<std::uint8_t> bits(len + 1, 0);
    for (std::size_t i = 0; i < len; ++i) {
        bits[i] = entropy[i];
    }
    bits[len] = ChecksumByte(entropy, len, cs_bits);

    out_mnemonic.clear();
    for (std::size_t w = 0; w < word_count; ++w) {
        std::uint16_t index = 0;
        for (std::size_t b = 0; b < kBitsPerWord; ++b) {
            const std::size_t bit = w * kBitsPerWord + b;
            const std::uint8_t value =
                static_cast<std::uint8_t>((bits[bit / 8] >> (7 - bit % 8)) & 1u);
            index = static_cast<std::uint16_t>((index << 1) | value);
        }

        const char* word = Bip39Word(index);
        if (word == nullptr) {
            bb_secure_zero(bits.data(), bits.size());
            out_mnemonic.clear();
            return false;
        }

        if (w != 0) {
            out_mnemonic.push_back(' ');
        }
        out_mnemonic.append(word);
    }

    bb_secure_zero(bits.data(), bits.size());
    return true;
}

bool Bip39Generate(unsigned words, std::string& out_mnemonic)
{
    std::size_t entropy_len = 0;
    if (words == kBip39Words12) {
        entropy_len = kBip39Entropy12;
    } else if (words == kBip39Words24) {
        entropy_len = kBip39Entropy24;
    } else {
        return false;
    }

    std::vector<std::uint8_t> entropy(entropy_len);
    if (RAND_bytes(entropy.data(), static_cast<int>(entropy.size())) != 1) {
        return false;
    }

    const bool ok = Bip39FromEntropy(entropy.data(), entropy.size(), out_mnemonic);
    bb_secure_zero(entropy.data(), entropy.size());
    return ok;
}

bool Bip39ToEntropy(std::string_view mnemonic,
                    std::uint8_t* out_entropy, std::size_t cap,
                    std::size_t* out_len)
{
    const std::vector<std::string_view> words = SplitWords(mnemonic);

    std::size_t entropy_len = 0;
    if (!EntropyLenForWords(words.size(), entropy_len)) {
        return false;
    }

    if (out_len != nullptr) {
        *out_len = entropy_len;
    }
    if (out_entropy == nullptr || cap < entropy_len) {
        return false;
    }

    const std::size_t cs_bits = entropy_len * 8 / 32;

    std::vector<std::uint8_t> bits(entropy_len + 1, 0);
    for (std::size_t w = 0; w < words.size(); ++w) {
        std::uint16_t index = 0;
        if (!Bip39FindWord(words[w], index)) {
            bb_secure_zero(bits.data(), bits.size());
            return false;
        }
        for (std::size_t b = 0; b < kBitsPerWord; ++b) {
            const std::size_t  bit   = w * kBitsPerWord + b;
            const std::uint8_t value =
                static_cast<std::uint8_t>((index >> (kBitsPerWord - 1 - b)) & 1u);
            bits[bit / 8] = static_cast<std::uint8_t>(
                bits[bit / 8] | static_cast<std::uint8_t>(value << (7 - bit % 8)));
        }
    }

    const std::uint8_t expected = ChecksumByte(bits.data(), entropy_len, cs_bits);
    const std::uint8_t mask     = static_cast<std::uint8_t>(0xFFu << (8 - cs_bits));

    if (static_cast<std::uint8_t>(bits[entropy_len] & mask) != expected) {
        bb_secure_zero(bits.data(), bits.size());
        return false;
    }

    for (std::size_t i = 0; i < entropy_len; ++i) {
        out_entropy[i] = bits[i];
    }
    bb_secure_zero(bits.data(), bits.size());
    return true;
}

bool Bip39Validate(std::string_view mnemonic)
{
    std::uint8_t entropy[kBip39Entropy24];
    std::size_t  len = 0;

    const bool ok = Bip39ToEntropy(mnemonic, entropy, sizeof entropy, &len);
    bb_secure_zero(entropy, sizeof entropy);
    return ok;
}

bool Bip39DeriveSeed(std::string_view mnemonic, std::string_view passphrase,
                     Bip39Seed& out_seed)
{
    std::string normalized = Bip39Normalize(mnemonic);
    if (normalized.empty()) {
        return false;
    }

    std::string salt("mnemonic");
    salt.append(passphrase.data(), passphrase.size());

    const int ok = PKCS5_PBKDF2_HMAC(
        normalized.data(), static_cast<int>(normalized.size()),
        reinterpret_cast<const unsigned char*>(salt.data()), static_cast<int>(salt.size()),
        2048, EVP_sha512(),
        static_cast<int>(out_seed.size()), out_seed.data());

    bb_secure_zero(&normalized[0], normalized.size());
    bb_secure_zero(&salt[0], salt.size());

    if (ok != 1) {
        bb_secure_zero(out_seed.data(), out_seed.size());
        return false;
    }
    return true;
}

}  // namespace bb
