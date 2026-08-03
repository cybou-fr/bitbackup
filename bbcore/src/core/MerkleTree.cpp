#include "core/MerkleTree.h"

namespace bb {
namespace {

constexpr std::uint8_t kDomainLeaf     = 0x00;
constexpr std::uint8_t kDomainInternal = 0x01;

/// Один уровень вверх. Нечётный последний узел поднимается как есть (§11).
bool ReduceLevel(const std::vector<Hash256>& level, std::vector<Hash256>& out_next)
{
    out_next.clear();
    out_next.reserve((level.size() + 1) / 2);

    for (std::size_t i = 0; i + 1 < level.size(); i += 2) {
        Hash256 node{};
        if (!MerkleNode(level[i], level[i + 1], node)) {
            return false;
        }
        out_next.push_back(node);
    }
    if (level.size() % 2 != 0) {
        out_next.push_back(level.back());
    }
    return true;
}

}  // namespace

bool MerkleLeaf(const void* shard_core, std::size_t len, Hash256& out_leaf)
{
    if (shard_core == nullptr && len != 0) {
        return false;
    }

    Blake3 hasher;
    hasher.UpdateU8(kDomainLeaf);
    hasher.Update(shard_core, len);
    return hasher.Finish(out_leaf);
}

bool MerkleNode(const Hash256& left, const Hash256& right, Hash256& out_node)
{
    Blake3 hasher;
    hasher.UpdateU8(kDomainInternal);
    hasher.Update(left.data(), left.size());
    hasher.Update(right.data(), right.size());
    return hasher.Finish(out_node);
}

bool MerkleRoot(const std::vector<Hash256>& leaves, Hash256& out_root)
{
    if (leaves.empty()) {
        return false;
    }

    std::vector<Hash256> level = leaves;
    std::vector<Hash256> next;

    while (level.size() > 1) {
        if (!ReduceLevel(level, next)) {
            return false;
        }
        level.swap(next);
    }

    out_root = level.front();
    return true;
}

bool MerklePath(const std::vector<Hash256>& leaves, std::size_t index,
                std::vector<Hash256>& out_path)
{
    out_path.clear();

    if (leaves.empty() || index >= leaves.size()) {
        return false;
    }

    std::vector<Hash256> level = leaves;
    std::vector<Hash256> next;
    std::size_t          position = index;

    while (level.size() > 1) {
        // Одиночный узел в конце уровня поднимается без пары, и соседа у него
        // на этом уровне просто нет — в путь ничего не добавляется.
        const bool has_sibling = !(position + 1 == level.size() && level.size() % 2 != 0);
        if (has_sibling) {
            out_path.push_back(level[position % 2 == 0 ? position + 1 : position - 1]);
        }

        if (!ReduceLevel(level, next)) {
            out_path.clear();
            return false;
        }
        level.swap(next);
        position /= 2;
    }

    return true;
}

bool MerkleVerify(const Hash256& leaf, std::size_t index, std::size_t leaf_count,
                  const std::vector<Hash256>& path, const Hash256& root)
{
    if (leaf_count == 0 || index >= leaf_count) {
        return false;
    }

    Hash256     current    = leaf;
    std::size_t position   = index;
    std::size_t level_size = leaf_count;
    std::size_t step       = 0;

    while (level_size > 1) {
        const bool has_sibling = !(position + 1 == level_size && level_size % 2 != 0);

        if (has_sibling) {
            if (step >= path.size()) {
                return false;
            }
            const Hash256& sibling = path[step++];

            Hash256 parent{};
            const bool ok = position % 2 == 0
                ? MerkleNode(current, sibling, parent)
                : MerkleNode(sibling, current, parent);
            if (!ok) {
                return false;
            }
            current = parent;
        }

        level_size = (level_size + 1) / 2;
        position /= 2;
    }

    // Лишние элементы пути — тоже отказ: принять путь с хвостом значило бы
    // допустить два разных доказательства для одного листа.
    if (step != path.size()) {
        return false;
    }

    return current == root;
}

}  // namespace bb
