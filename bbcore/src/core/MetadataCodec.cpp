#include "core/MetadataCodec.h"

#include "util/Cbor.h"

#include <cstring>

namespace bb {
namespace {

/// Ключи словарей §13. Порядок в каждом списке — канонический по RFC 8949
/// §4.2.1: сначала по длине кодированного ключа, потом побайтово. Он же
/// проверяется читателем, поэтому ошибка в порядке ловится round-trip тестом.
constexpr std::size_t kTopLevelFields = 7;
constexpr std::size_t kFileFields     = 8;
constexpr std::size_t kStreamFields   = 2;
constexpr std::size_t kSplitFields    = 4;
constexpr std::size_t kRsFields       = 3;
constexpr std::size_t kMerkleFields   = 2;
constexpr std::size_t kSelfFields     = 3;

/// Верхняя граница на число пар в словаре при разборе. Схема фиксирована, и
/// принимать словарь на миллион ключей незачем.
constexpr std::size_t kMaxMapEntries = 32;

bool WriteUint32(std::vector<std::uint8_t>& out, std::uint32_t value)
{
    out.push_back(static_cast<std::uint8_t>(value >> 24));
    out.push_back(static_cast<std::uint8_t>(value >> 16));
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
    return true;
}

std::uint32_t ReadUint32(const std::uint8_t* p)
{
    return static_cast<std::uint32_t>(p[0]) << 24
         | static_cast<std::uint32_t>(p[1]) << 16
         | static_cast<std::uint32_t>(p[2]) << 8
         | static_cast<std::uint32_t>(p[3]);
}

void EncodeBody(const ChunkMetadata& m, CborWriter& w)
{
    w.MapHeader(kTopLevelFields);

    w.Text("v");
    w.Uint(m.version);

    w.Text("rs");
    w.MapHeader(kRsFields);
    w.Text("data");    w.Uint(m.rs_data);
    w.Text("chunks");  w.Uint(m.chunk_count);
    w.Text("parity");  w.Uint(m.rs_parity);

    w.Text("file");
    w.MapHeader(kFileFields);
    w.Text("hash");       w.Bytes(m.content_hash.data(), m.content_hash.size());
    w.Text("name");       w.Text(m.file_name);
    w.Text("path");       w.Text(m.file_path);
    w.Text("size");       w.Uint(m.file_size);
    w.Text("created");    w.Int(m.created);
    w.Text("instance");   w.Bytes(m.file_instance.data(), m.file_instance.size());
    w.Text("modified");   w.Int(m.modified);
    w.Text("attributes"); w.Uint(m.attributes);

    w.Text("self");
    w.MapHeader(kSelfFields);
    w.Text("index");    w.Uint(m.self_index);
    w.Text("stripe");   w.Uint(m.self_stripe);
    w.Text("position"); w.Uint(m.self_position);

    w.Text("split");
    w.MapHeader(kSplitFields);
    w.Text("avg");   w.Uint(m.split.avg);
    w.Text("max");   w.Uint(m.split.max);
    w.Text("min");   w.Uint(m.split.min);
    w.Text("align"); w.Uint(m.split.align);

    w.Text("merkle");
    w.MapHeader(kMerkleFields);
    w.Text("path");
    w.ArrayHeader(m.merkle_path.size());
    for (const Hash256& node : m.merkle_path) {
        w.Bytes(node.data(), node.size());
    }
    w.Text("root");
    w.Bytes(m.merkle_root.data(), m.merkle_root.size());

    w.Text("stream");
    w.MapHeader(kStreamFields);
    w.Text("transform");   w.Bytes(m.transform_id.data(), m.transform_id.size());
    w.Text("stored_size"); w.Uint(m.stored_size);
}

/// Разбор одного словаря с фиксированным набором ключей. Отсутствие или
/// повторение любого поля — отказ: неполные метаданные означали бы чанк,
/// который нельзя ни проверить, ни разложить обратно.
template <typename Handler>
bool DecodeMap(CborReader& r, std::size_t expected_fields, Handler handler)
{
    std::size_t count = 0;
    if (!r.ReadMapHeader(count, kMaxMapEntries) || count != expected_fields) {
        return false;
    }

    std::string_view previous;
    for (std::size_t i = 0; i < count; ++i) {
        std::string_view key;
        if (!r.ReadMapKey(key, previous) || !handler(key)) {
            return false;
        }
        previous = key;
    }
    return true;
}

bool DecodeBody(CborReader& r, ChunkMetadata& m)
{
    bool ok = true;

    auto rs = [&](std::string_view key) {
        std::uint64_t value = 0;
        if (!r.ReadUint(value) || value > 0xFFFFFFFFull) {
            return false;
        }
        if (key == "data")        { m.rs_data     = static_cast<std::uint32_t>(value); }
        else if (key == "chunks") { m.chunk_count = static_cast<std::uint32_t>(value); }
        else if (key == "parity") { m.rs_parity   = static_cast<std::uint32_t>(value); }
        else                      { return false; }
        return true;
    };

    auto file = [&](std::string_view key) {
        if (key == "hash") {
            return r.ReadBytes(m.content_hash.data(), m.content_hash.size());
        }
        if (key == "instance") {
            return r.ReadBytes(m.file_instance.data(), m.file_instance.size());
        }
        if (key == "name" || key == "path") {
            std::string_view text;
            const std::size_t limit =
                key == "name" ? kMetadataMaxNameLen : kMetadataMaxPathLen;
            if (!r.ReadText(text, limit)) {
                return false;
            }
            // Нулевой байт внутри пути превратил бы строку в C ABI в обрезок,
            // и файл восстановился бы не туда.
            if (text.find('\0') != std::string_view::npos) {
                return false;
            }
            (key == "name" ? m.file_name : m.file_path).assign(text);
            return true;
        }
        if (key == "size") {
            return r.ReadUint(m.file_size);
        }
        if (key == "created")  { return r.ReadInt(m.created); }
        if (key == "modified") { return r.ReadInt(m.modified); }
        if (key == "attributes") {
            std::uint64_t value = 0;
            if (!r.ReadUint(value) || value > 0xFFFFFFFFull) {
                return false;
            }
            m.attributes = static_cast<std::uint32_t>(value);
            return true;
        }
        return false;
    };

    auto self = [&](std::string_view key) {
        std::uint64_t value = 0;
        if (!r.ReadUint(value)) {
            return false;
        }
        if (key == "index" && value <= 0xFFFFFFFFull) {
            m.self_index = static_cast<std::uint32_t>(value);
        } else if (key == "stripe" && value <= 0xFFFFFFFFull) {
            m.self_stripe = static_cast<std::uint32_t>(value);
        } else if (key == "position" && value <= 0xFFFFull) {
            m.self_position = static_cast<std::uint16_t>(value);
        } else {
            return false;
        }
        return true;
    };

    auto split = [&](std::string_view key) {
        std::uint64_t value = 0;
        if (!r.ReadUint(value) || value > 0xFFFFFFFFull) {
            return false;
        }
        const std::uint32_t narrowed = static_cast<std::uint32_t>(value);
        if (key == "avg")        { m.split.avg   = narrowed; }
        else if (key == "max")   { m.split.max   = narrowed; }
        else if (key == "min")   { m.split.min   = narrowed; }
        else if (key == "align") { m.split.align = narrowed; }
        else                     { return false; }
        return true;
    };

    auto merkle = [&](std::string_view key) {
        if (key == "root") {
            return r.ReadBytes(m.merkle_root.data(), m.merkle_root.size());
        }
        if (key == "path") {
            std::size_t nodes = 0;
            if (!r.ReadArrayHeader(nodes, kMetadataMaxPathNodes)) {
                return false;
            }
            m.merkle_path.resize(nodes);
            for (Hash256& node : m.merkle_path) {
                if (!r.ReadBytes(node.data(), node.size())) {
                    return false;
                }
            }
            return true;
        }
        return false;
    };

    auto stream = [&](std::string_view key) {
        if (key == "transform") {
            return r.ReadBytes(m.transform_id.data(), m.transform_id.size());
        }
        if (key == "stored_size") {
            return r.ReadUint(m.stored_size);
        }
        return false;
    };

    auto top = [&](std::string_view key) {
        if (key == "v") {
            std::uint64_t value = 0;
            if (!r.ReadUint(value) || value > 0xFFFFFFFFull) {
                return false;
            }
            m.version = static_cast<std::uint32_t>(value);
            return true;
        }
        if (key == "rs")     { return DecodeMap(r, kRsFields, rs); }
        if (key == "file")   { return DecodeMap(r, kFileFields, file); }
        if (key == "self")   { return DecodeMap(r, kSelfFields, self); }
        if (key == "split")  { return DecodeMap(r, kSplitFields, split); }
        if (key == "merkle") { return DecodeMap(r, kMerkleFields, merkle); }
        if (key == "stream") { return DecodeMap(r, kStreamFields, stream); }
        return false;
    };

    ok = DecodeMap(r, kTopLevelFields, top);
    return ok;
}

/// Согласованность полей между собой. Разобранный CBOR ещё не означает
/// осмысленных метаданных, а дальше по ним будут выводиться ключи.
bool IsConsistent(const ChunkMetadata& m)
{
    if (m.version != BB_FORMAT_VERSION) {
        return false;
    }
    if (m.rs_data == 0 || m.rs_parity == 0 || m.chunk_count == 0) {
        return false;
    }
    if (m.rs_data + m.rs_parity > 0xFFFFu) {
        return false;
    }
    if (m.chunk_count > BB_MAX_CHUNKS) {
        return false;
    }
    if (m.self_position >= m.rs_data + m.rs_parity) {
        return false;
    }
    // §12: индекс не независимое поле, а функция stripe и position.
    // Расхождение означало бы чанк, чьё имя не соответствует его месту.
    if (m.self_index != m.self_stripe * (m.rs_data + m.rs_parity) + m.self_position) {
        return false;
    }
    if (!SplitProfileIsValid(m.split)) {
        return false;
    }
    if (m.file_name.empty() && m.file_size != 0) {
        return false;
    }
    return true;
}

}  // namespace

bool MetadataSizeClass(std::size_t payload_len, std::size_t* out_class)
{
    if (out_class == nullptr) {
        return false;
    }

    const std::size_t total = payload_len + kMetadataLengthPrefix;
    for (std::size_t klass : {static_cast<std::size_t>(BB_META_CLASS_MIN),
                              static_cast<std::size_t>(BB_META_CLASS_MID),
                              static_cast<std::size_t>(BB_META_CLASS_MAX)}) {
        if (total <= klass) {
            *out_class = klass;
            return true;
        }
    }
    return false;
}

bb_status MetadataEncode(const ChunkMetadata&       metadata,
                         std::vector<std::uint8_t>& out_plaintext)
{
    out_plaintext.clear();

    if (metadata.file_name.size() > kMetadataMaxNameLen
     || metadata.file_path.size() > kMetadataMaxPathLen
     || metadata.merkle_path.size() > kMetadataMaxPathNodes) {
        return BB_ERR_INVALID_ARG;
    }
    if (!IsConsistent(metadata)) {
        return BB_ERR_INVALID_ARG;
    }

    CborWriter writer;
    EncodeBody(metadata, writer);

    const std::vector<std::uint8_t>& body = writer.Buffer();

    std::size_t klass = 0;
    if (!MetadataSizeClass(body.size(), &klass)) {
        return BB_ERR_BUFFER_TOO_SMALL;
    }

    out_plaintext.reserve(klass);
    WriteUint32(out_plaintext, static_cast<std::uint32_t>(body.size()));
    out_plaintext.insert(out_plaintext.end(), body.begin(), body.end());
    out_plaintext.resize(klass, 0);

    return BB_OK;
}

bb_status MetadataDecode(const std::uint8_t* plaintext, std::size_t len,
                         ChunkMetadata&      out_metadata)
{
    out_metadata = ChunkMetadata{};

    if (plaintext == nullptr) {
        return BB_ERR_INVALID_ARG;
    }
    if (len != BB_META_CLASS_MIN && len != BB_META_CLASS_MID
     && len != BB_META_CLASS_MAX) {
        return BB_ERR_BAD_CONTAINER;
    }

    const std::uint32_t payload_len = ReadUint32(plaintext);
    if (payload_len > len - kMetadataLengthPrefix) {
        return BB_ERR_BAD_CONTAINER;
    }

    // Дополнение обязано быть нулями: иначе в нём поместился бы скрытый канал,
    // а метаданные перестали бы быть функцией своего содержимого.
    for (std::size_t i = kMetadataLengthPrefix + payload_len; i < len; ++i) {
        if (plaintext[i] != 0) {
            return BB_ERR_BAD_CONTAINER;
        }
    }

    CborReader reader(plaintext + kMetadataLengthPrefix, payload_len);
    if (!DecodeBody(reader, out_metadata)) {
        return BB_ERR_BAD_CONTAINER;
    }

    // Хвост после CBOR внутри полезной части — тоже отказ: он означал бы, что
    // payload_len не соответствует содержимому.
    if (!reader.AtEnd()) {
        return BB_ERR_BAD_CONTAINER;
    }

    if (!IsConsistent(out_metadata)) {
        return BB_ERR_BAD_CONTAINER;
    }

    return BB_OK;
}

}  // namespace bb
