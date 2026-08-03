// Merkle-дерево — §11.
//
// Независимой реализации здесь нет: BLAKE3 в стандартной библиотеке Python
// отсутствует. Поэтому вектора не берутся ниоткуда, а структура проверяется
// свойствами — согласованностью пути с корнем, отказом на подмене и явным
// построением маленьких деревьев вручную из MerkleLeaf и MerkleNode.
//
// Сам BLAKE3 при этом проверен официальными векторами в test_blake3.cpp, а
// доменные байты — отдельным тестом там же.

#include "Testing.h"

#include "core/MerkleTree.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> Core(std::size_t index, std::size_t len = 64)
{
    std::vector<std::uint8_t> core(len);
    for (std::size_t i = 0; i < len; ++i) {
        core[i] = static_cast<std::uint8_t>((index * 31 + i * 7) & 0xFF);
    }
    return core;
}

std::vector<bb::Hash256> Leaves(std::size_t count)
{
    std::vector<bb::Hash256> leaves;
    for (std::size_t i = 0; i < count; ++i) {
        const std::vector<std::uint8_t> core = Core(i);
        bb::Hash256                     leaf{};
        if (!bb::MerkleLeaf(core.data(), core.size(), leaf)) {
            return {};
        }
        leaves.push_back(leaf);
    }
    return leaves;
}

}  // namespace

// Дерево из одного листа — корень это сам лист, путь пуст. Так выглядит любой
// файл, уложившийся в один фрагмент.
BB_TEST(merkle_single_leaf_is_its_own_root)
{
    const std::vector<bb::Hash256> leaves = Leaves(1);

    bb::Hash256 root{};
    BB_CHECK(bb::MerkleRoot(leaves, root));
    BB_CHECK_EQ(std::memcmp(root.data(), leaves[0].data(), root.size()), 0);

    std::vector<bb::Hash256> path;
    BB_CHECK(bb::MerklePath(leaves, 0, path));
    BB_CHECK(path.empty());
    BB_CHECK(bb::MerkleVerify(leaves[0], 0, 1, path, root));
}

BB_TEST(merkle_two_leaves_build_one_node)
{
    const std::vector<bb::Hash256> leaves = Leaves(2);

    bb::Hash256 expected{};
    BB_CHECK(bb::MerkleNode(leaves[0], leaves[1], expected));

    bb::Hash256 root{};
    BB_CHECK(bb::MerkleRoot(leaves, root));
    BB_CHECK_EQ(std::memcmp(root.data(), expected.data(), root.size()), 0);
}

// Нечётный узел поднимается наверх без изменений (§11). Три листа дают
// node(node(l0, l1), l2), а не node(node(l0,l1), node(l2,l2)): дублирование
// последнего листа — известная уязвимость к подмене длины дерева.
BB_TEST(merkle_odd_node_is_promoted_not_duplicated)
{
    const std::vector<bb::Hash256> leaves = Leaves(3);

    bb::Hash256 pair{};
    bb::Hash256 expected{};
    BB_CHECK(bb::MerkleNode(leaves[0], leaves[1], pair));
    BB_CHECK(bb::MerkleNode(pair, leaves[2], expected));

    bb::Hash256 root{};
    BB_CHECK(bb::MerkleRoot(leaves, root));
    BB_CHECK_EQ(std::memcmp(root.data(), expected.data(), root.size()), 0);

    // Именно то, чего быть не должно.
    bb::Hash256 duplicated_pair{};
    bb::Hash256 duplicated_root{};
    BB_CHECK(bb::MerkleNode(leaves[2], leaves[2], duplicated_pair));
    BB_CHECK(bb::MerkleNode(pair, duplicated_pair, duplicated_root));
    BB_CHECK(std::memcmp(root.data(), duplicated_root.data(), root.size()) != 0);
}

// Главное свойство: путь любого листа обязан сойтись с корнем при любом числе
// листьев, включая неудобные — 3, 5, 7, 11.
BB_TEST(merkle_every_path_verifies_for_every_size)
{
    for (std::size_t count = 1; count <= 17; ++count) {
        const std::vector<bb::Hash256> leaves = Leaves(count);

        bb::Hash256 root{};
        BB_CHECK(bb::MerkleRoot(leaves, root));

        for (std::size_t i = 0; i < count; ++i) {
            std::vector<bb::Hash256> path;
            BB_CHECK(bb::MerklePath(leaves, i, path));

            if (!bb::MerkleVerify(leaves[i], i, count, path, root)) {
                std::printf("    leaf %zu of %zu failed to verify\n", i, count);
                ++bb_failures;
                return;
            }
        }
    }
}

// Ради этого дерево и строится: подменённый parity shard, у которого нет
// AEAD-тега, обязан быть отвергнут ДО Reed–Solomon.
BB_TEST(merkle_rejects_a_tampered_leaf)
{
    const std::size_t              count  = 11;
    const std::vector<bb::Hash256> leaves = Leaves(count);

    bb::Hash256 root{};
    BB_CHECK(bb::MerkleRoot(leaves, root));

    for (std::size_t i = 0; i < count; ++i) {
        std::vector<bb::Hash256> path;
        BB_CHECK(bb::MerklePath(leaves, i, path));

        bb::Hash256 tampered = leaves[i];
        tampered[0] ^= 0x01;
        BB_CHECK(!bb::MerkleVerify(tampered, i, count, path, root));
    }
}

// Подменённый чанк с самосогласованным собственным корнем не должен пройти
// проверку против корня, взятого из первого расшифрованного чанка (§11).
BB_TEST(merkle_rejects_a_foreign_root)
{
    const std::vector<bb::Hash256> mine  = Leaves(8);
    std::vector<bb::Hash256>       their = Leaves(8);
    their[3][0] ^= 0x01;

    bb::Hash256 my_root{};
    bb::Hash256 their_root{};
    BB_CHECK(bb::MerkleRoot(mine, my_root));
    BB_CHECK(bb::MerkleRoot(their, their_root));
    BB_CHECK(std::memcmp(my_root.data(), their_root.data(), my_root.size()) != 0);

    std::vector<bb::Hash256> their_path;
    BB_CHECK(bb::MerklePath(their, 3, their_path));

    // Их лист с их путём сходится с их корнем — и не сходится с нашим.
    BB_CHECK(bb::MerkleVerify(their[3], 3, 8, their_path, their_root));
    BB_CHECK(!bb::MerkleVerify(their[3], 3, 8, their_path, my_root));
}

// Индекс задаёт сторону подстановки соседа. Перепутанная сторона обязана
// сломать проверку — иначе доказательство годилось бы для чужой позиции.
BB_TEST(merkle_rejects_a_wrong_index)
{
    const std::size_t              count  = 8;
    const std::vector<bb::Hash256> leaves = Leaves(count);

    bb::Hash256 root{};
    BB_CHECK(bb::MerkleRoot(leaves, root));

    std::vector<bb::Hash256> path;
    BB_CHECK(bb::MerklePath(leaves, 2, path));

    BB_CHECK(bb::MerkleVerify(leaves[2], 2, count, path, root));
    BB_CHECK(!bb::MerkleVerify(leaves[2], 3, count, path, root));
    BB_CHECK(!bb::MerkleVerify(leaves[2], 0, count, path, root));
    BB_CHECK(!bb::MerkleVerify(leaves[2], count, count, path, root));
}

// Путь с хвостом — второе доказательство для того же листа. Принимать такое
// нельзя: доказательство обязано быть единственным.
BB_TEST(merkle_rejects_a_malformed_path)
{
    const std::size_t              count  = 8;
    const std::vector<bb::Hash256> leaves = Leaves(count);

    bb::Hash256 root{};
    BB_CHECK(bb::MerkleRoot(leaves, root));

    std::vector<bb::Hash256> path;
    BB_CHECK(bb::MerklePath(leaves, 5, path));

    std::vector<bb::Hash256> longer = path;
    longer.push_back(leaves[0]);
    BB_CHECK(!bb::MerkleVerify(leaves[5], 5, count, longer, root));

    std::vector<bb::Hash256> shorter = path;
    shorter.pop_back();
    BB_CHECK(!bb::MerkleVerify(leaves[5], 5, count, shorter, root));

    std::vector<bb::Hash256> swapped = path;
    swapped[0] = path[1];
    swapped[1] = path[0];
    BB_CHECK(!bb::MerkleVerify(leaves[5], 5, count, swapped, root));
}

// У полного дерева путь ровно log2(n); у неполного бывает короче, потому что
// одиночный узел поднимается без пары. Значит длину пути нельзя вычислить из
// числа чанков — метаданные обязаны нести его целиком.
BB_TEST(merkle_path_length_is_not_derivable_from_count)
{
    const std::vector<bb::Hash256> full = Leaves(8);
    for (std::size_t i = 0; i < full.size(); ++i) {
        std::vector<bb::Hash256> path;
        BB_CHECK(bb::MerklePath(full, i, path));
        BB_CHECK_EQ(path.size(), std::size_t{3});
    }

    const std::vector<bb::Hash256> ragged = Leaves(5);
    std::vector<bb::Hash256>       first;
    std::vector<bb::Hash256>       last;
    BB_CHECK(bb::MerklePath(ragged, 0, first));
    BB_CHECK(bb::MerklePath(ragged, 4, last));
    BB_CHECK(first.size() > last.size());
}

BB_TEST(merkle_rejects_empty_input)
{
    const std::vector<bb::Hash256> empty;

    bb::Hash256 root{};
    BB_CHECK(!bb::MerkleRoot(empty, root));

    std::vector<bb::Hash256> path;
    BB_CHECK(!bb::MerklePath(empty, 0, path));
    BB_CHECK(!bb::MerklePath(Leaves(4), 4, path));
    BB_CHECK(!bb::MerkleVerify(root, 0, 0, path, root));
}

// Лист нулевой длины законен: пустой файл даёт фрагмент нулевой длины, а его
// shard core состоит из одного AEAD-тега.
BB_TEST(merkle_accepts_an_empty_core)
{
    bb::Hash256 leaf{};
    BB_CHECK(bb::MerkleLeaf(nullptr, 0, leaf));

    bb::Hash256 root{};
    BB_CHECK(bb::MerkleRoot({leaf}, root));
    BB_CHECK_EQ(std::memcmp(root.data(), leaf.data(), root.size()), 0);

    BB_CHECK(!bb::MerkleLeaf(nullptr, 16, leaf));
}
