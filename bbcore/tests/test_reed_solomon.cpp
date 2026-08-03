// Reed–Solomon над GF(2^8) — §10, §29, §30.
//
// Векторы поля и матрицы Коши посчитаны независимой реализацией на Python:
// арифметика GF(2^8) с полиномом 0x11D и матрица Коши воспроизводятся в
// полсотни строк, поэтому вторая реализация здесь возможна и сделана.
//
// Главная проверка — фаззинг из milestone фазы 5: случайные stripes, случайные
// потери до parity элементов, 10 000 итераций, побайтовое совпадение.

#include "Testing.h"

#include "redundancy/Gf256.h"
#include "redundancy/ReedSolomon.h"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {

/// xorshift с постоянным семенем: фаззинг обязан воспроизводиться, иначе
/// упавший прогон нечем повторить.
class Random {
public:
    explicit Random(std::uint64_t seed) : state_(seed) {}

    std::uint32_t Next()
    {
        state_ ^= state_ << 13;
        state_ ^= state_ >> 7;
        state_ ^= state_ << 17;
        return static_cast<std::uint32_t>(state_ >> 32);
    }

    std::uint32_t Below(std::uint32_t bound)
    {
        return bound == 0 ? 0 : Next() % bound;
    }

private:
    std::uint64_t state_;
};

std::vector<std::uint8_t*> Pointers(std::vector<std::vector<std::uint8_t>>& shards,
                                    std::size_t first, std::size_t count)
{
    std::vector<std::uint8_t*> pointers;
    for (std::size_t i = 0; i < count; ++i) {
        pointers.push_back(shards[first + i].data());
    }
    return pointers;
}

}  // namespace

// ---------------------------------------------------------------------------
// Поле
// ---------------------------------------------------------------------------

BB_TEST(gf256_matches_independent_implementation)
{
    BB_CHECK_EQ(static_cast<int>(bb::GfMul(0x53, 0xca)), 0x8f);
    BB_CHECK_EQ(static_cast<int>(bb::GfMul(0x02, 0x80)), 0x1d);

    BB_CHECK_EQ(static_cast<int>(bb::GfInv(0x01)), 0x01);
    BB_CHECK_EQ(static_cast<int>(bb::GfInv(0x02)), 0x8e);
    BB_CHECK_EQ(static_cast<int>(bb::GfInv(0x53)), 0x8c);
    BB_CHECK_EQ(static_cast<int>(bb::GfInv(0xff)), 0xfd);
}

// Аксиомы поля на всех 65 536 парах: дешевле, чем гадать, где именно таблицы
// разошлись.
BB_TEST(gf256_is_a_field)
{
    for (int a = 0; a < 256; ++a) {
        const std::uint8_t x = static_cast<std::uint8_t>(a);

        BB_CHECK_EQ(static_cast<int>(bb::GfMul(x, 0)), 0);
        BB_CHECK_EQ(static_cast<int>(bb::GfMul(x, 1)), a);
        BB_CHECK_EQ(static_cast<int>(bb::GfAdd(x, x)), 0);

        if (a != 0) {
            BB_CHECK_EQ(static_cast<int>(bb::GfMul(x, bb::GfInv(x))), 1);
            BB_CHECK_EQ(static_cast<int>(bb::GfDiv(x, x)), 1);
        }
    }

    for (int a = 0; a < 256; ++a) {
        for (int b = 0; b < 256; ++b) {
            const std::uint8_t x = static_cast<std::uint8_t>(a);
            const std::uint8_t y = static_cast<std::uint8_t>(b);

            if (bb::GfMul(x, y) != bb::GfMul(y, x)) {
                std::printf("    multiplication is not commutative at %02x %02x\n", a, b);
                ++bb_failures;
                return;
            }
            if (b != 0 && bb::GfMul(bb::GfDiv(x, y), y) != x) {
                std::printf("    division is not inverse of multiplication at %02x %02x\n",
                            a, b);
                ++bb_failures;
                return;
            }
        }
    }
}

BB_TEST(gf256_log_and_exp_are_inverse)
{
    const bb::Gf256Tables& t = bb::Gf256();

    for (int i = 1; i < 256; ++i) {
        BB_CHECK_EQ(static_cast<int>(t.exp[t.log[i]]), i);
    }
    for (int i = 0; i < 255; ++i) {
        BB_CHECK_EQ(static_cast<int>(t.log[t.exp[i]]), i);
        BB_CHECK_EQ(static_cast<int>(t.exp[i + 255]), static_cast<int>(t.exp[i]));
    }
}

// ---------------------------------------------------------------------------
// Матрица и кодирование
// ---------------------------------------------------------------------------

BB_TEST(reed_solomon_parity_matches_independent_implementation)
{
    bb::ReedSolomon rs;
    BB_CHECK(bb::ReedSolomon::Create(8, 3, rs));

    const std::size_t                          len = 16;
    std::vector<std::vector<std::uint8_t>>     shards(11, std::vector<std::uint8_t>(len));
    for (std::size_t j = 0; j < 8; ++j) {
        for (std::size_t b = 0; b < len; ++b) {
            shards[j][b] = static_cast<std::uint8_t>((j * 37 + b * 11 + 5) & 0xFF);
        }
    }

    std::vector<const std::uint8_t*> data;
    for (std::size_t j = 0; j < 8; ++j) {
        data.push_back(shards[j].data());
    }
    std::vector<std::uint8_t*> parity = Pointers(shards, 8, 3);

    BB_CHECK(rs.Encode(data.data(), parity.data(), len));

    BB_CHECK_STR(bb::test::Hex(shards[8].data(), len).c_str(),
                 "3a1e5a1aa7c0a2feb299f99af7f6bcb0");
    BB_CHECK_STR(bb::test::Hex(shards[9].data(), len).c_str(),
                 "97b392247a585ad52f31792674df1c54");
    BB_CHECK_STR(bb::test::Hex(shards[10].data(), len).c_str(),
                 "dfcebe812b21d6eb7141d33f6cf43609");
}

BB_TEST(reed_solomon_rejects_impossible_parameters)
{
    bb::ReedSolomon rs;

    BB_CHECK(!bb::ReedSolomon::Create(0, 3, rs));
    BB_CHECK(!bb::ReedSolomon::Create(8, 0, rs));
    BB_CHECK(!bb::ReedSolomon::Create(254, 3, rs));   // 257 > 256
    BB_CHECK(bb::ReedSolomon::Create(253, 3, rs));    // ровно 256 можно
    BB_CHECK(bb::ReedSolomon::Create(1, 1, rs));
}

// ---------------------------------------------------------------------------
// Восстановление
// ---------------------------------------------------------------------------

namespace {

/// Один прогон: закодировать, потерять указанные шарды, восстановить, сверить.
bool RecoverAfterLosses(bb::ReedSolomon& rs, std::size_t shard_len,
                        const std::vector<std::uint32_t>& lost,
                        Random& random)
{
    const std::uint32_t total = rs.TotalShards();

    std::vector<std::vector<std::uint8_t>> shards(
        total, std::vector<std::uint8_t>(shard_len));
    for (std::uint32_t j = 0; j < rs.DataShards(); ++j) {
        for (std::size_t b = 0; b < shard_len; ++b) {
            shards[j][b] = static_cast<std::uint8_t>(random.Next());
        }
    }

    std::vector<const std::uint8_t*> data;
    for (std::uint32_t j = 0; j < rs.DataShards(); ++j) {
        data.push_back(shards[j].data());
    }
    std::vector<std::uint8_t*> parity = Pointers(shards, rs.DataShards(),
                                                 rs.ParityShards());
    if (!rs.Encode(data.data(), parity.data(), shard_len)) {
        return false;
    }

    const std::vector<std::vector<std::uint8_t>> original = shards;

    std::unique_ptr<bool[]> present(new bool[total]);
    for (std::uint32_t i = 0; i < total; ++i) {
        present[i] = true;
    }
    for (std::uint32_t index : lost) {
        present[index] = false;
        // Затираем мусором: восстановление обязано не смотреть на потерянное.
        for (std::size_t b = 0; b < shard_len; ++b) {
            shards[index][b] = static_cast<std::uint8_t>(random.Next());
        }
    }

    std::vector<std::uint8_t*> all;
    for (std::uint32_t i = 0; i < total; ++i) {
        all.push_back(shards[i].data());
    }

    if (rs.Decode(all.data(), present.get(), shard_len) != BB_OK) {
        return false;
    }

    return shards == original;
}

}  // namespace

BB_TEST(reed_solomon_recovers_every_combination_of_three_losses)
{
    bb::ReedSolomon rs;
    BB_CHECK(bb::ReedSolomon::Create(8, 3, rs));

    Random random(0x5DEECE66Dull);

    // Все сочетания трёх потерь из одиннадцати — 165 штук.
    for (std::uint32_t a = 0; a < 11; ++a) {
        for (std::uint32_t b = a + 1; b < 11; ++b) {
            for (std::uint32_t c = b + 1; c < 11; ++c) {
                if (!RecoverAfterLosses(rs, 64, {a, b, c}, random)) {
                    std::printf("    lost %u %u %u and did not recover\n", a, b, c);
                    ++bb_failures;
                    return;
                }
            }
        }
    }
}

BB_TEST(reed_solomon_recovers_fewer_losses)
{
    bb::ReedSolomon rs;
    BB_CHECK(bb::ReedSolomon::Create(8, 3, rs));

    Random random(1);

    for (std::uint32_t a = 0; a < 11; ++a) {
        BB_CHECK(RecoverAfterLosses(rs, 100, {a}, random));
    }
    for (std::uint32_t a = 0; a < 11; ++a) {
        for (std::uint32_t b = a + 1; b < 11; ++b) {
            if (!RecoverAfterLosses(rs, 33, {a, b}, random)) {
                std::printf("    lost %u %u and did not recover\n", a, b);
                ++bb_failures;
                return;
            }
        }
    }
    BB_CHECK(RecoverAfterLosses(rs, 64, {}, random));
}

// Четвёртая потеря невосстановима — и обязана быть отвергнута, а не молча
// превращена в мусор. §10 говорит об этом прямо: гарантия действует на каждую
// stripe отдельно.
BB_TEST(reed_solomon_refuses_more_losses_than_parity)
{
    bb::ReedSolomon rs;
    BB_CHECK(bb::ReedSolomon::Create(8, 3, rs));

    const std::size_t len   = 32;
    const std::uint32_t total = rs.TotalShards();

    std::vector<std::vector<std::uint8_t>> shards(
        total, std::vector<std::uint8_t>(len, 0x7E));
    std::vector<std::uint8_t*> all;
    for (std::uint32_t i = 0; i < total; ++i) {
        all.push_back(shards[i].data());
    }

    std::unique_ptr<bool[]> present(new bool[total]);
    for (std::uint32_t i = 0; i < total; ++i) {
        present[i] = i >= 4;
    }
    BB_CHECK_EQ(rs.Decode(all.data(), present.get(), len), BB_ERR_UNRECOVERABLE);

    // Полная потеря — тоже отказ, а не пустой результат.
    for (std::uint32_t i = 0; i < total; ++i) {
        present[i] = false;
    }
    BB_CHECK_EQ(rs.Decode(all.data(), present.get(), len), BB_ERR_UNRECOVERABLE);
}

// Milestone фазы 5: случайные stripes, случайные потери до трёх элементов,
// 10 000 итераций, побайтовое совпадение.
BB_TEST(reed_solomon_fuzz_ten_thousand_stripes)
{
    bb::ReedSolomon rs;
    BB_CHECK(bb::ReedSolomon::Create(8, 3, rs));

    Random random(0xC0FFEEull);

    for (int iteration = 0; iteration < 10000; ++iteration) {
        const std::size_t shard_len = 1 + random.Below(200);
        const std::uint32_t losses  = random.Below(4);

        std::vector<std::uint32_t> lost;
        while (lost.size() < losses) {
            const std::uint32_t candidate = random.Below(11);
            bool                seen      = false;
            for (std::uint32_t existing : lost) {
                seen = seen || existing == candidate;
            }
            if (!seen) {
                lost.push_back(candidate);
            }
        }

        if (!RecoverAfterLosses(rs, shard_len, lost, random)) {
            std::printf("    iteration %d failed: len %zu, %u losses\n",
                        iteration, shard_len, losses);
            ++bb_failures;
            return;
        }
    }
}

// Другие конфигурации формат пока не использует, но API их допускает, и
// вырожденные случаи ломаются первыми.
BB_TEST(reed_solomon_fuzz_other_configurations)
{
    const std::uint32_t configurations[][2] = {
        {1, 1}, {2, 1}, {4, 2}, {16, 4}, {8, 8}, {32, 3}};

    Random random(0xBADC0DEull);

    for (const auto& configuration : configurations) {
        bb::ReedSolomon rs;
        BB_CHECK(bb::ReedSolomon::Create(configuration[0], configuration[1], rs));

        for (int iteration = 0; iteration < 200; ++iteration) {
            const std::size_t   shard_len = 1 + random.Below(64);
            const std::uint32_t losses    = random.Below(configuration[1] + 1);

            std::vector<std::uint32_t> lost;
            while (lost.size() < losses) {
                const std::uint32_t candidate = random.Below(rs.TotalShards());
                bool                seen      = false;
                for (std::uint32_t existing : lost) {
                    seen = seen || existing == candidate;
                }
                if (!seen) {
                    lost.push_back(candidate);
                }
            }

            if (!RecoverAfterLosses(rs, shard_len, lost, random)) {
                std::printf("    %u+%u failed at iteration %d\n",
                            configuration[0], configuration[1], iteration);
                ++bb_failures;
                return;
            }
        }
    }
}

// Пустая stripe законна: пустой файл даёт фрагмент нулевой длины, и его core
// после дополнения тоже может оказаться пустым в вырожденном случае.
BB_TEST(reed_solomon_handles_zero_length_shards)
{
    bb::ReedSolomon rs;
    BB_CHECK(bb::ReedSolomon::Create(8, 3, rs));

    std::vector<std::uint8_t>  storage(11, 0);
    std::vector<std::uint8_t*> all;
    for (std::size_t i = 0; i < 11; ++i) {
        all.push_back(&storage[i]);
    }

    std::vector<const std::uint8_t*> data;
    for (std::size_t i = 0; i < 8; ++i) {
        data.push_back(&storage[i]);
    }
    std::vector<std::uint8_t*> parity;
    for (std::size_t i = 8; i < 11; ++i) {
        parity.push_back(&storage[i]);
    }

    BB_CHECK(rs.Encode(data.data(), parity.data(), 0));

    std::unique_ptr<bool[]> present(new bool[11]);
    for (std::size_t i = 0; i < 11; ++i) {
        present[i] = i != 0;
    }
    BB_CHECK_EQ(rs.Decode(all.data(), present.get(), 0), BB_OK);
}

BB_TEST(reed_solomon_rejects_null_buffers)
{
    bb::ReedSolomon rs;
    BB_CHECK(bb::ReedSolomon::Create(8, 3, rs));

    std::vector<std::uint8_t>  storage(11 * 8, 0);
    std::vector<std::uint8_t*> all;
    for (std::size_t i = 0; i < 11; ++i) {
        all.push_back(storage.data() + i * 8);
    }
    std::unique_ptr<bool[]> present(new bool[11]);
    for (std::size_t i = 0; i < 11; ++i) {
        present[i] = true;
    }

    BB_CHECK_EQ(rs.Decode(nullptr, present.get(), 8), BB_ERR_INVALID_ARG);
    BB_CHECK_EQ(rs.Decode(all.data(), nullptr, 8), BB_ERR_INVALID_ARG);

    all[3] = nullptr;
    BB_CHECK_EQ(rs.Decode(all.data(), present.get(), 8), BB_ERR_INVALID_ARG);
}
