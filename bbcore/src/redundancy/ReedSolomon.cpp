#include "redundancy/ReedSolomon.h"

#include "redundancy/Gf256.h"

#include <cstring>

namespace bb {
namespace {

/// Обращение квадратной матрицы над GF(2^8) методом Гаусса–Жордана.
/// Матрица n×n построчно; результат на месте.
bool InvertMatrix(std::vector<std::uint8_t>& m, std::size_t n)
{
    std::vector<std::uint8_t> inverse(n * n, 0);
    for (std::size_t i = 0; i < n; ++i) {
        inverse[i * n + i] = 1;
    }

    for (std::size_t column = 0; column < n; ++column) {
        // Поиск ненулевого ведущего элемента. У подматрицы Коши он обязан
        // найтись, но матрица приходит из данных, и полагаться на это нельзя.
        std::size_t pivot = column;
        while (pivot < n && m[pivot * n + column] == 0) {
            ++pivot;
        }
        if (pivot == n) {
            return false;
        }

        if (pivot != column) {
            for (std::size_t j = 0; j < n; ++j) {
                std::swap(m[column * n + j], m[pivot * n + j]);
                std::swap(inverse[column * n + j], inverse[pivot * n + j]);
            }
        }

        const std::uint8_t scale = GfInv(m[column * n + column]);
        for (std::size_t j = 0; j < n; ++j) {
            m[column * n + j]       = GfMul(m[column * n + j], scale);
            inverse[column * n + j] = GfMul(inverse[column * n + j], scale);
        }

        for (std::size_t row = 0; row < n; ++row) {
            if (row == column) {
                continue;
            }
            const std::uint8_t factor = m[row * n + column];
            if (factor == 0) {
                continue;
            }
            for (std::size_t j = 0; j < n; ++j) {
                m[row * n + j] = GfAdd(m[row * n + j],
                                       GfMul(m[column * n + j], factor));
                inverse[row * n + j] = GfAdd(inverse[row * n + j],
                                             GfMul(inverse[column * n + j], factor));
            }
        }
    }

    m.swap(inverse);
    return true;
}

/// out += coefficient * in, побайтово.
void MultiplyAdd(std::uint8_t* out, const std::uint8_t* in,
                 std::uint8_t coefficient, std::size_t len)
{
    if (coefficient == 0) {
        return;
    }
    const Gf256Tables& t   = Gf256();
    const int          log = t.log[coefficient];

    for (std::size_t i = 0; i < len; ++i) {
        if (in[i] != 0) {
            out[i] = static_cast<std::uint8_t>(
                out[i] ^ t.exp[log + static_cast<int>(t.log[in[i]])]);
        }
    }
}

}  // namespace

std::uint8_t ReedSolomon::Coefficient(std::uint32_t i, std::uint32_t j) const
{
    // x_i = i, y_j = parity_ + j; множества не пересекаются, поэтому XOR
    // никогда не ноль и обратный элемент существует.
    const std::uint8_t x = static_cast<std::uint8_t>(i);
    const std::uint8_t y = static_cast<std::uint8_t>(parity_ + j);
    return GfInv(GfAdd(x, y));
}

bool ReedSolomon::Create(std::uint32_t data, std::uint32_t parity, ReedSolomon& out)
{
    if (data == 0 || parity == 0) {
        return false;
    }
    if (static_cast<std::uint64_t>(data) + parity > 256) {
        return false;
    }

    out.data_   = data;
    out.parity_ = parity;
    out.matrix_.assign(static_cast<std::size_t>(parity) * data, 0);

    for (std::uint32_t i = 0; i < parity; ++i) {
        for (std::uint32_t j = 0; j < data; ++j) {
            out.matrix_[static_cast<std::size_t>(i) * data + j] = out.Coefficient(i, j);
        }
    }
    return true;
}

bool ReedSolomon::Encode(const std::uint8_t* const* data,
                         std::uint8_t* const*       parity,
                         std::size_t                shard_len) const
{
    if (data_ == 0 || data == nullptr || parity == nullptr) {
        return false;
    }
    if (shard_len == 0) {
        return true;  // stripe из пустых шардов: считать нечего, и это законно
    }

    for (std::uint32_t i = 0; i < parity_; ++i) {
        if (parity[i] == nullptr) {
            return false;
        }
        std::memset(parity[i], 0, shard_len);

        for (std::uint32_t j = 0; j < data_; ++j) {
            if (data[j] == nullptr) {
                return false;
            }
            MultiplyAdd(parity[i], data[j],
                        matrix_[static_cast<std::size_t>(i) * data_ + j], shard_len);
        }
    }
    return true;
}

bb_status ReedSolomon::Decode(std::uint8_t* const* shards,
                              const bool*          present,
                              std::size_t          shard_len) const
{
    if (data_ == 0 || shards == nullptr || present == nullptr) {
        return BB_ERR_INVALID_ARG;
    }

    const std::uint32_t total = TotalShards();

    std::uint32_t available = 0;
    for (std::uint32_t i = 0; i < total; ++i) {
        if (shards[i] == nullptr) {
            return BB_ERR_INVALID_ARG;
        }
        if (present[i]) {
            ++available;
        }
    }

    if (available < data_) {
        return BB_ERR_UNRECOVERABLE;
    }
    if (available == total) {
        return BB_OK;  // терять нечего
    }
    if (shard_len == 0) {
        return BB_OK;  // восстанавливать нечего, длины нулевые
    }

    // Берём первые data_ уцелевших шардов и собираем из их строк квадратную
    // матрицу. Строка data shard — это строка единичной матрицы, строка parity
    // shard — строка Коши.
    std::vector<std::uint32_t> chosen;
    chosen.reserve(data_);
    for (std::uint32_t i = 0; i < total && chosen.size() < data_; ++i) {
        if (present[i]) {
            chosen.push_back(i);
        }
    }

    std::vector<std::uint8_t> square(static_cast<std::size_t>(data_) * data_, 0);
    for (std::uint32_t row = 0; row < data_; ++row) {
        const std::uint32_t shard = chosen[row];
        std::uint8_t* const line  = square.data() + static_cast<std::size_t>(row) * data_;

        if (shard < data_) {
            line[shard] = 1;
        } else {
            const std::uint32_t parity_row = shard - data_;
            for (std::uint32_t j = 0; j < data_; ++j) {
                line[j] = matrix_[static_cast<std::size_t>(parity_row) * data_ + j];
            }
        }
    }

    if (!InvertMatrix(square, data_)) {
        return BB_ERR_UNRECOVERABLE;
    }

    // Сначала восстанавливаются недостающие data shards: parity считается по
    // ним, поэтому порядок обязателен.
    std::vector<std::uint8_t> recovered;
    for (std::uint32_t i = 0; i < data_; ++i) {
        if (present[i]) {
            continue;
        }
        recovered.assign(shard_len, 0);
        for (std::uint32_t j = 0; j < data_; ++j) {
            MultiplyAdd(recovered.data(), shards[chosen[j]],
                        square[static_cast<std::size_t>(i) * data_ + j], shard_len);
        }
        std::memcpy(shards[i], recovered.data(), shard_len);
    }

    // Теперь недостающие parity — уже по восстановленным data.
    for (std::uint32_t i = 0; i < parity_; ++i) {
        const std::uint32_t index = data_ + i;
        if (present[index]) {
            continue;
        }
        std::memset(shards[index], 0, shard_len);
        for (std::uint32_t j = 0; j < data_; ++j) {
            MultiplyAdd(shards[index], shards[j],
                        matrix_[static_cast<std::size_t>(i) * data_ + j], shard_len);
        }
    }

    return BB_OK;
}

}  // namespace bb
