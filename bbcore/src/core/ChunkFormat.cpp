#include "core/ChunkFormat.h"

#include "core/StripeBuilder.h"

#include <openssl/rand.h>

#include <cstring>
#include <string_view>

namespace bb {
namespace {

constexpr std::string_view kLabelMetaAad = "bbk/1/meta-aad";

/// AAD метаданных (§14):
///   "bbk/1/meta-aad" || identity_id || object_name || u32be(len_metadata)
///
/// len_shard_core оттуда убран вместе с открытым заголовком: он брался из того
/// же header, который AAD и покрывал, то есть утверждал «прочитанная длина
/// равна прочитанной длине». Длина ядра проверяется сверкой с раскладкой.
std::vector<std::uint8_t> BuildMetadataAad(const Hash256&    identity,
                                           const ObjectName& object_name,
                                           std::uint32_t     len_metadata)
{
    std::vector<std::uint8_t> aad;
    aad.reserve(kLabelMetaAad.size() + identity.size() + object_name.size() + 4);

    aad.insert(aad.end(), kLabelMetaAad.begin(), kLabelMetaAad.end());
    aad.insert(aad.end(), identity.begin(), identity.end());
    aad.insert(aad.end(), object_name.begin(), object_name.end());

    aad.push_back(static_cast<std::uint8_t>(len_metadata >> 24));
    aad.push_back(static_cast<std::uint8_t>(len_metadata >> 16));
    aad.push_back(static_cast<std::uint8_t>(len_metadata >> 8));
    aad.push_back(static_cast<std::uint8_t>(len_metadata));

    return aad;
}

/// Suite, которые клиент умеет. Перебирается при вскрытии: suite_id нигде не
/// лежит открыто, он входит только в transcript combiner'а (§15).
constexpr std::uint16_t kKnownSuites[] = {BB_SUITE_ID};

constexpr std::size_t kMetadataClasses[] = {
    BB_META_CLASS_MIN, BB_META_CLASS_MID, BB_META_CLASS_MAX};

}  // namespace

bb_status ChunkBuild(const ChunkBuildInput& input, std::vector<std::uint8_t>& out)
{
    out.clear();

    if (input.recipient_kem == nullptr || input.recipient_classic == nullptr
     || input.recipient_identity == nullptr || input.k_file == nullptr
     || input.file_id == nullptr || input.object_name == nullptr
     || input.metadata == nullptr) {
        return BB_ERR_INVALID_ARG;
    }
    if (input.shard_core == nullptr && input.shard_core_len != 0) {
        return BB_ERR_INVALID_ARG;
    }

    // Имя обязано быть выводимо из K_file и индекса: иначе объект нельзя
    // будет найти, а при чтении он не сойдётся с перебором индексов.
    ObjectName expected_name{};
    if (!DeriveObjectName(*input.k_file, input.metadata->self_index, expected_name)) {
        return BB_ERR_INTERNAL;
    }
    if (expected_name != *input.object_name) {
        return BB_ERR_INVALID_ARG;
    }

    std::vector<std::uint8_t> metadata_plain;
    const bb_status encoded = MetadataEncode(*input.metadata, metadata_plain);
    if (encoded != BB_OK) {
        return encoded;
    }

    const std::size_t len_metadata = metadata_plain.size() + kAeadTagLen;

    HybridEnvelope envelope;
    const bb_status sealed = HybridSeal(*input.recipient_kem, *input.recipient_classic,
                                        *input.recipient_identity, input.suite_id,
                                        *input.k_file, *input.file_id, envelope);
    if (sealed != BB_OK) {
        return sealed;
    }

    AeadKey   k_meta{};
    AeadNonce n_meta{};
    if (!DeriveMetadataKey(*input.k_file, input.metadata->self_index, k_meta, n_meta)) {
        bb_secure_zero(metadata_plain.data(), metadata_plain.size());
        return BB_ERR_INTERNAL;
    }

    const std::vector<std::uint8_t> aad = BuildMetadataAad(
        *input.recipient_identity, *input.object_name,
        static_cast<std::uint32_t>(len_metadata));

    const std::size_t padding = input.metadata->padding;

    out.resize(kChunkPrefixLen + len_metadata + input.shard_core_len + padding);

    std::memcpy(out.data(), envelope.ct_mlkem.data(), envelope.ct_mlkem.size());
    std::memcpy(out.data() + kMlKemCiphertextLen,
                envelope.epk_x25519.data(), envelope.epk_x25519.size());
    std::memcpy(out.data() + kMlKemCiphertextLen + kX25519KeyLen,
                envelope.wrapped.data(), envelope.wrapped.size());

    std::size_t produced = 0;
    const bool  ok = AeadSeal(k_meta, n_meta, aad.data(), aad.size(),
                              metadata_plain.data(), metadata_plain.size(),
                              out.data() + kChunkPrefixLen, len_metadata, &produced)
                  && produced == len_metadata;

    bb_secure_zero(metadata_plain.data(), metadata_plain.size());
    bb_secure_zero(k_meta.data(), k_meta.size());
    bb_secure_zero(n_meta.data(), n_meta.size());

    if (!ok) {
        out.clear();
        return BB_ERR_INTERNAL;
    }

    if (input.shard_core_len != 0) {
        std::memcpy(out.data() + kChunkPrefixLen + len_metadata,
                    input.shard_core, input.shard_core_len);
    }

    // Дополнение — именно случайные байты, а не нули: объект обязан оставаться
    // равномерным шумом по всей длине.
    if (padding != 0) {
        std::uint8_t* tail = out.data() + kChunkPrefixLen + len_metadata
                           + input.shard_core_len;
        if (RAND_bytes(tail, static_cast<int>(padding)) != 1) {
            out.clear();
            return BB_ERR_INTERNAL;
        }
    }

    return BB_OK;
}

bb_status ChunkOpen(const MlKemKeyPair&  self_kem,
                    const X25519KeyPair& self_classic,
                    const Hash256&       self_identity,
                    const Hash256&       name_identity,
                    const ObjectName&    object_name,
                    const std::uint8_t*  blob,
                    std::size_t          blob_len,
                    std::uint64_t        object_size,
                    ChunkOpened&         out)
{
    out = ChunkOpened{};

    if (blob == nullptr) {
        return BB_ERR_INVALID_ARG;
    }
    if (name_identity != self_identity) {
        return BB_ERR_WRONG_IDENTITY;
    }
    if (blob_len < kChunkPrefixLen + BB_META_CLASS_MIN + BB_TAG_LEN) {
        return BB_ERR_BAD_CONTAINER;
    }
    if (object_size < blob_len) {
        return BB_ERR_BAD_CONTAINER;
    }

    HybridEnvelope envelope;
    std::memcpy(envelope.ct_mlkem.data(), blob, kMlKemCiphertextLen);
    std::memcpy(envelope.epk_x25519.data(), blob + kMlKemCiphertextLen, kX25519KeyLen);
    std::memcpy(envelope.wrapped.data(),
                blob + kMlKemCiphertextLen + kX25519KeyLen, kEnvelopeWrappedLen);

    // Перебор suite: он входит в transcript, поэтому чужой suite просто не
    // вскроет wrapped. Декапсуляция ML-KEM внутри HybridOpen от suite не
    // зависит, так что перебор стоит одной выжимки SHAKE на вариант.
    bb_status status = BB_ERR_DECRYPT_FAILED;
    for (std::uint16_t suite : kKnownSuites) {
        status = HybridOpen(self_kem, self_classic, self_identity, suite,
                            self_identity.data(), envelope, out.k_file, out.file_id);
        if (status == BB_OK) {
            out.suite_id = suite;
            break;
        }
    }
    if (status != BB_OK) {
        return BB_ERR_DECRYPT_FAILED;
    }

    // K_meta зависит от канонического индекса, а тот лежит внутри метаданных.
    // Круг разрывается именем: оно тоже выведено из K_file и индекса (§5).
    std::uint32_t index = 0;
    bool          found = false;
    for (std::uint32_t candidate = 0; candidate < BB_MAX_CHUNKS; ++candidate) {
        ObjectName derived{};
        if (!DeriveObjectName(out.k_file, candidate, derived)) {
            return BB_ERR_INTERNAL;
        }
        if (derived == object_name) {
            index = candidate;
            found = true;
            break;
        }
    }
    if (!found) {
        // Имя не выводится из K_file — объект подставлен под чужим именем.
        return BB_ERR_DECRYPT_FAILED;
    }

    AeadKey   k_meta{};
    AeadNonce n_meta{};
    if (!DeriveMetadataKey(out.k_file, index, k_meta, n_meta)) {
        return BB_ERR_INTERNAL;
    }

    std::vector<std::uint8_t> plain;
    std::size_t               chosen_class = 0;

    for (std::size_t klass : kMetadataClasses) {
        const std::size_t region = klass + kAeadTagLen;
        if (kChunkPrefixLen + region > blob_len) {
            continue;  // столько не прочитано — нужен второй range-запрос
        }

        const std::vector<std::uint8_t> aad = BuildMetadataAad(
            self_identity, object_name, static_cast<std::uint32_t>(region));

        plain.assign(klass, 0);
        std::size_t produced = 0;

        if (AeadOpen(k_meta, n_meta, aad.data(), aad.size(),
                     blob + kChunkPrefixLen, region,
                     plain.data(), plain.size(), &produced)
         && produced == klass) {
            chosen_class = klass;
            break;
        }
    }

    bb_secure_zero(k_meta.data(), k_meta.size());
    bb_secure_zero(n_meta.data(), n_meta.size());

    if (chosen_class == 0) {
        bb_secure_zero(plain.data(), plain.size());
        return BB_ERR_DECRYPT_FAILED;
    }

    const bb_status decoded = MetadataDecode(plain.data(), plain.size(), out.metadata);
    bb_secure_zero(plain.data(), plain.size());
    if (decoded != BB_OK) {
        return decoded;
    }

    // Индекс из метаданных обязан совпасть с найденным по имени: расхождение
    // означало бы чанк, чьё имя не соответствует его месту (§12).
    if (out.metadata.self_index != index) {
        return BB_ERR_BAD_CONTAINER;
    }

    out.metadata_class = chosen_class;
    out.core_offset    = kChunkPrefixLen + chosen_class + kAeadTagLen;

    const std::uint64_t tail = object_size - out.core_offset;
    if (out.core_offset > object_size || tail < out.metadata.padding) {
        return BB_ERR_BAD_CONTAINER;
    }
    out.core_length = static_cast<std::size_t>(tail - out.metadata.padding);

    return BB_OK;
}

bb_status ChunkObjectNames(const FileKey&           k_file,
                           const ChunkMetadata&     metadata,
                           std::vector<ObjectName>& out_names)
{
    out_names.clear();

    if (metadata.rs_data == 0 || metadata.rs_parity == 0
     || metadata.chunk_count == 0 || metadata.chunk_count > BB_MAX_CHUNKS) {
        return BB_ERR_INVALID_ARG;
    }

    // Из chunk_count однозначно восстанавливается число фрагментов, а из него —
    // какие канонические индексы существуют. У неполной последней stripe часть
    // позиций пуста, поэтому ряд индексов не сплошной (§10, §12).
    std::uint64_t fragments = 0;
    if (!StripeFragmentCount(metadata.chunk_count, metadata.rs_data,
                             metadata.rs_parity, &fragments)) {
        return BB_ERR_BAD_CONTAINER;
    }

    const std::uint32_t slots = metadata.rs_data + metadata.rs_parity;
    const std::uint64_t stripes =
        (fragments + metadata.rs_data - 1) / metadata.rs_data;

    out_names.reserve(metadata.chunk_count);

    for (std::uint64_t stripe = 0; stripe < stripes; ++stripe) {
        const std::uint64_t first = stripe * metadata.rs_data;
        const std::uint64_t count =
            fragments - first < metadata.rs_data ? fragments - first : metadata.rs_data;

        for (std::uint64_t j = 0; j < count; ++j) {
            ObjectName name{};
            if (!DeriveObjectName(k_file,
                                  static_cast<std::uint32_t>(stripe * slots + j), name)) {
                return BB_ERR_INTERNAL;
            }
            out_names.push_back(name);
        }
        for (std::uint32_t p = 0; p < metadata.rs_parity; ++p) {
            ObjectName name{};
            if (!DeriveObjectName(k_file,
                                  static_cast<std::uint32_t>(
                                      stripe * slots + metadata.rs_data + p), name)) {
                return BB_ERR_INTERNAL;
            }
            out_names.push_back(name);
        }
    }

    if (out_names.size() != metadata.chunk_count) {
        out_names.clear();
        return BB_ERR_BAD_CONTAINER;
    }
    return BB_OK;
}

}  // namespace bb
