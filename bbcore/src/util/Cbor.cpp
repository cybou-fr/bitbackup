#include "util/Cbor.h"

#include <cstring>

namespace bb {
namespace {

constexpr std::uint8_t kMajorUint  = 0;
constexpr std::uint8_t kMajorNint  = 1;
constexpr std::uint8_t kMajorBytes = 2;
constexpr std::uint8_t kMajorText  = 3;
constexpr std::uint8_t kMajorArray = 4;
constexpr std::uint8_t kMajorMap   = 5;

bool IsValidUtf8Bytes(const std::uint8_t* data, std::size_t size)
{
    std::size_t i = 0;
    while (i < size) {
        const std::uint8_t lead = data[i++];
        if (lead <= 0x7F) {
            continue;
        }

        std::uint32_t codepoint = 0;
        std::size_t continuation = 0;
        if (lead >= 0xC2 && lead <= 0xDF) {
            codepoint = lead & 0x1Fu;
            continuation = 1;
        } else if (lead >= 0xE0 && lead <= 0xEF) {
            codepoint = lead & 0x0Fu;
            continuation = 2;
        } else if (lead >= 0xF0 && lead <= 0xF4) {
            codepoint = lead & 0x07u;
            continuation = 3;
        } else {
            return false;
        }
        if (size - i < continuation) {
            return false;
        }
        for (std::size_t n = 0; n < continuation; ++n) {
            const std::uint8_t byte = data[i++];
            if ((byte & 0xC0u) != 0x80u) {
                return false;
            }
            codepoint = (codepoint << 6) | (byte & 0x3Fu);
        }
        const std::uint32_t minimum = continuation == 1 ? 0x80u
                                    : continuation == 2 ? 0x800u : 0x10000u;
        if (codepoint < minimum || codepoint > 0x10FFFFu
         || (codepoint >= 0xD800u && codepoint <= 0xDFFFu)) {
            return false;
        }
    }
    return true;
}

}  // namespace

bool Utf8IsValid(std::string_view text)
{
    return IsValidUtf8Bytes(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

// ---------------------------------------------------------------------------
// Писатель
// ---------------------------------------------------------------------------

void CborWriter::Head(std::uint8_t major, std::uint64_t value)
{
    const std::uint8_t prefix = static_cast<std::uint8_t>(major << 5);

    if (value < 24) {
        buffer_.push_back(static_cast<std::uint8_t>(prefix | value));
    } else if (value <= 0xFFu) {
        buffer_.push_back(static_cast<std::uint8_t>(prefix | 24));
        buffer_.push_back(static_cast<std::uint8_t>(value));
    } else if (value <= 0xFFFFu) {
        buffer_.push_back(static_cast<std::uint8_t>(prefix | 25));
        buffer_.push_back(static_cast<std::uint8_t>(value >> 8));
        buffer_.push_back(static_cast<std::uint8_t>(value));
    } else if (value <= 0xFFFFFFFFu) {
        buffer_.push_back(static_cast<std::uint8_t>(prefix | 26));
        for (int shift = 24; shift >= 0; shift -= 8) {
            buffer_.push_back(static_cast<std::uint8_t>(value >> shift));
        }
    } else {
        buffer_.push_back(static_cast<std::uint8_t>(prefix | 27));
        for (int shift = 56; shift >= 0; shift -= 8) {
            buffer_.push_back(static_cast<std::uint8_t>(value >> shift));
        }
    }
}

void CborWriter::Uint(std::uint64_t value)
{
    Head(kMajorUint, value);
}

void CborWriter::Int(std::int64_t value)
{
    if (value >= 0) {
        Head(kMajorUint, static_cast<std::uint64_t>(value));
    } else {
        // -1 - n, где n — кодируемое значение. Через unsigned, чтобы не
        // получить неопределённое поведение на INT64_MIN.
        const std::uint64_t magnitude =
            ~static_cast<std::uint64_t>(value);  // = -1 - value
        Head(kMajorNint, magnitude);
    }
}

void CborWriter::Bytes(const void* data, std::size_t len)
{
    Head(kMajorBytes, len);
    if (len != 0 && data != nullptr) {
        const std::uint8_t* p = static_cast<const std::uint8_t*>(data);
        buffer_.insert(buffer_.end(), p, p + len);
    }
}

void CborWriter::Text(std::string_view text)
{
    Head(kMajorText, text.size());
    buffer_.insert(buffer_.end(), text.begin(), text.end());
}

void CborWriter::ArrayHeader(std::size_t count)
{
    Head(kMajorArray, count);
}

void CborWriter::MapHeader(std::size_t count)
{
    Head(kMajorMap, count);
}

// ---------------------------------------------------------------------------
// Читатель
// ---------------------------------------------------------------------------

bool CborReader::ReadHead(std::uint8_t& out_major, std::uint64_t& out_value)
{
    if (offset_ >= size_) {
        return false;
    }

    const std::uint8_t initial    = data_[offset_++];
    const std::uint8_t major      = static_cast<std::uint8_t>(initial >> 5);
    const std::uint8_t additional = static_cast<std::uint8_t>(initial & 0x1F);

    std::uint64_t value = 0;
    std::size_t   width = 0;

    if (additional < 24) {
        value = additional;
    } else if (additional == 24) {
        width = 1;
    } else if (additional == 25) {
        width = 2;
    } else if (additional == 26) {
        width = 4;
    } else if (additional == 27) {
        width = 8;
    } else {
        return false;  // 28..30 зарезервированы, 31 — неопределённая длина
    }

    if (width != 0) {
        if (size_ - offset_ < width) {
            return false;
        }
        for (std::size_t i = 0; i < width; ++i) {
            value = (value << 8) | data_[offset_ + i];
        }
        offset_ += width;

        // Каноническая форма: заголовок обязан быть минимальной длины.
        // Иначе одно и то же число имело бы несколько представлений, а с ним
        // и метаданные — несколько кодировок при одном содержимом.
        const std::uint64_t minimum =
            width == 1 ? 24u
          : width == 2 ? 0x100u
          : width == 4 ? 0x10000u
                       : 0x100000000ull;
        if (value < minimum) {
            return false;
        }
    }

    out_major = major;
    out_value = value;
    return true;
}

bool CborReader::ReadUint(std::uint64_t& out)
{
    std::uint8_t  major = 0;
    std::uint64_t value = 0;
    if (!ReadHead(major, value) || major != kMajorUint) {
        return false;
    }
    out = value;
    return true;
}

bool CborReader::ReadInt(std::int64_t& out)
{
    std::uint8_t  major = 0;
    std::uint64_t value = 0;
    if (!ReadHead(major, value)) {
        return false;
    }

    if (major == kMajorUint) {
        if (value > static_cast<std::uint64_t>(INT64_MAX)) {
            return false;
        }
        out = static_cast<std::int64_t>(value);
        return true;
    }
    if (major == kMajorNint) {
        if (value > static_cast<std::uint64_t>(INT64_MAX)) {
            return false;
        }
        out = -1 - static_cast<std::int64_t>(value);
        return true;
    }
    return false;
}

bool CborReader::ReadBytes(std::uint8_t* out, std::size_t expected_len)
{
    std::uint8_t  major = 0;
    std::uint64_t length = 0;
    if (!ReadHead(major, length) || major != kMajorBytes) {
        return false;
    }
    if (length != expected_len || size_ - offset_ < expected_len) {
        return false;
    }

    if (expected_len != 0) {
        std::memcpy(out, data_ + offset_, expected_len);
    }
    offset_ += expected_len;
    return true;
}

bool CborReader::ReadText(std::string_view& out, std::size_t max_len)
{
    std::uint8_t  major  = 0;
    std::uint64_t length = 0;
    if (!ReadHead(major, length) || major != kMajorText) {
        return false;
    }

    // Потолок проверяется до обращения к буферу: длина пришла из недоверенных
    // данных и может быть какой угодно.
    if (length > max_len || length > size_ - offset_) {
        return false;
    }

    if (!IsValidUtf8Bytes(data_ + offset_, static_cast<std::size_t>(length))) {
        return false;
    }

    out = std::string_view(reinterpret_cast<const char*>(data_ + offset_),
                           static_cast<std::size_t>(length));
    offset_ += static_cast<std::size_t>(length);
    return true;
}

bool CborReader::ReadArrayHeader(std::size_t& out_count, std::size_t max_count)
{
    std::uint8_t  major = 0;
    std::uint64_t count = 0;
    if (!ReadHead(major, count) || major != kMajorArray || count > max_count) {
        return false;
    }
    out_count = static_cast<std::size_t>(count);
    return true;
}

bool CborReader::ReadMapHeader(std::size_t& out_count, std::size_t max_count)
{
    std::uint8_t  major = 0;
    std::uint64_t count = 0;
    if (!ReadHead(major, count) || major != kMajorMap || count > max_count) {
        return false;
    }
    out_count = static_cast<std::size_t>(count);
    return true;
}

bool CborReader::ReadMapKey(std::string_view& out, std::string_view previous)
{
    std::string_view key;
    if (!ReadText(key, 64)) {
        return false;
    }

    // Каноническое упорядочение RFC 8949 §4.2.1 — по кодированному ключу, то
    // есть сначала по длине, потом побайтово. Строгое возрастание заодно
    // запрещает дубликаты, а с ними и вопрос «какое из двух значений верное».
    if (!previous.empty()) {
        const bool ordered = previous.size() < key.size()
            || (previous.size() == key.size() && previous < key);
        if (!ordered) {
            return false;
        }
    }

    out = key;
    return true;
}

}  // namespace bb
