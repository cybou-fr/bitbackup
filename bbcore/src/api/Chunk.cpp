// Реализация bb_chunk_* из плоского C ABI.

#include "bbcore/bbcore.h"

#include "api/IdentityHandle.h"
#include "core/ChunkFormat.h"

#include <cstring>
#include <vector>

namespace {

/// Разобрать полное имя объекта "<identity>.<name>.bbk" на две половины.
bool ParseName(const char* text, bb::Hash256& out_identity, bb::ObjectName& out_name)
{
    return bb_object_name_parse(text, out_identity.data(), out_name.data()) == BB_OK;
}

void CopyString(char* out, std::size_t cap, const std::string& value)
{
    const std::size_t length = value.size() < cap - 1 ? value.size() : cap - 1;
    std::memcpy(out, value.data(), length);
    out[length] = '\0';
}

bb_status Open(const bb_identity* identity, const char* object_name,
               const std::uint8_t* blob, std::size_t blob_len,
               std::uint64_t object_size, bb::ChunkOpened& out)
{
    if (identity == nullptr || object_name == nullptr || blob == nullptr) {
        return BB_ERR_INVALID_ARG;
    }
    if (!identity->impl.IsValid() || !identity->impl.HasPrivateKey()) {
        return BB_ERR_INVALID_ARG;
    }

    bb::Hash256    name_identity{};
    bb::ObjectName name{};
    if (!ParseName(object_name, name_identity, name)) {
        return BB_ERR_INVALID_ARG;
    }

    return bb::ChunkOpen(identity->impl.Kem(), identity->impl.Classic(),
                         identity->impl.Id(), name_identity, name,
                         blob, blob_len, object_size, out);
}

}  // namespace

BB_API size_t BB_CALL bb_header_probe_size(void)
{
    // Префикс 1680 (ML-KEM ct 1568 + epk 32 + wrapped 80) плюс метаданные
    // младшего класса с тегом — 5792 байта. 8 KiB покрывают это с запасом.
    // Если ни один класс не уложился в прочитанное, вызывающий делает второй
    // range-запрос; на практике это редкий случай (§16).
    static_assert(bb::kChunkPrefixLen + BB_META_CLASS_MIN + BB_TAG_LEN <= 8192,
                  "probe size must cover the prefix and the smallest metadata class");
    return 8192;
}

BB_API bb_status BB_CALL bb_chunk_inspect(
    const bb_identity* identity,
    const char*        object_name,
    const uint8_t*     blob,
    size_t             blob_len,
    uint64_t           object_size,
    bb_chunk_info*     out_info)
{
    if (out_info == nullptr) {
        return BB_ERR_INVALID_ARG;
    }

    bb::ChunkOpened   opened;
    const bb_status   status = Open(identity, object_name, blob, blob_len,
                                    object_size, opened);
    if (status != BB_OK) {
        return status;
    }

    const bb::ChunkMetadata& m = opened.metadata;

    std::memset(out_info, 0, sizeof *out_info);
    out_info->struct_size = sizeof *out_info;

    std::memcpy(out_info->identity_id, identity->impl.Id().data(), BB_ID_LEN);
    std::memcpy(out_info->file_id, opened.file_id.data(), BB_HASH_LEN);
    std::memcpy(out_info->file_instance_id, m.file_instance.data(), BB_INSTANCE_ID_LEN);
    std::memcpy(out_info->content_hash, m.content_hash.data(), BB_HASH_LEN);
    std::memcpy(out_info->merkle_root, m.merkle_root.data(), BB_HASH_LEN);

    CopyString(out_info->file_name, sizeof out_info->file_name, m.file_name);
    CopyString(out_info->file_path, sizeof out_info->file_path, m.file_path);

    out_info->plain_size  = m.file_size;
    out_info->stored_size = m.stored_size;
    out_info->created     = m.created;
    out_info->modified    = m.modified;
    out_info->attributes  = m.attributes;

    std::memcpy(out_info->transform_id, m.transform_id.data(), BB_TRANSFORM_ID_LEN);

    // Отображение transform_id на bb_compression временное: §7 ещё не
    // реализован и точную кодировку не задаёт. Нули означают «без сжатия».
    const bool no_transform =
        m.transform_id == bb::TransformId{0, 0, 0, 0};
    out_info->compression = no_transform ? BB_COMPRESSION_NONE : BB_COMPRESSION_ZSTD;

    // pad_shards в метаданных §13 не предусмотрен, поэтому восстановить его из
    // одного чанка нечем. Пока сообщается 0; см. долг в ROADMAP.
    out_info->pad_shards = 0;

    out_info->rs_data     = m.rs_data;
    out_info->rs_parity   = m.rs_parity;
    out_info->chunk_count = m.chunk_count;

    out_info->self_index     = m.self_index;
    out_info->self_stripe    = m.self_stripe;
    out_info->self_position  = m.self_position;
    out_info->self_is_parity = m.self_position >= m.rs_data ? 1 : 0;

    // ML-DSA-87 ещё не реализован, подписанных transfer-чанков не бывает.
    out_info->signed_transfer = 0;

    return BB_OK;
}

BB_API bb_status BB_CALL bb_chunk_object_names(
    const bb_identity* identity,
    const char*        object_name,
    const uint8_t*     blob,
    size_t             blob_len,
    uint64_t           object_size,
    char*              out_names,
    size_t             out_names_cap,
    uint32_t*          out_count)
{
    bb::ChunkOpened opened;
    const bb_status status = Open(identity, object_name, blob, blob_len,
                                  object_size, opened);
    if (status != BB_OK) {
        return status;
    }

    std::vector<bb::ObjectName> names;
    const bb_status listed = bb::ChunkObjectNames(opened.k_file, opened.metadata, names);
    if (listed != BB_OK) {
        return listed;
    }

    if (out_count != nullptr) {
        *out_count = static_cast<uint32_t>(names.size());
    }

    const size_t needed = names.size() * BB_OBJECT_NAME_MAX;
    if (out_names == nullptr || out_names_cap < needed) {
        return BB_ERR_BUFFER_TOO_SMALL;
    }

    bb::Hash256    name_identity{};
    bb::ObjectName ignored{};
    if (!ParseName(object_name, name_identity, ignored)) {
        return BB_ERR_INVALID_ARG;
    }

    for (std::size_t i = 0; i < names.size(); ++i) {
        char* slot = out_names + i * BB_OBJECT_NAME_MAX;
        const bb_status formatted = bb_object_name_format(
            name_identity.data(), names[i].data(), slot, BB_OBJECT_NAME_MAX);
        if (formatted != BB_OK) {
            return formatted;
        }
    }

    return BB_OK;
}
