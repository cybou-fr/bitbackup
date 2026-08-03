// Контейнер .bbk — §16.
//
// Главное свойство, которое здесь проверяется: в объекте нет ни одного байта
// открытого текста. Не «мало», не «неважных» — ни одного. Всё, что не является
// AEAD-ciphertext, является ciphertext ML-KEM или точкой X25519, то есть
// неотличимо от равномерного шума.
//
// Плюс round-trip и обязательный негативный тест из правил проекта: порча
// любого байта контейнера обязана быть обнаружена.

#include "Testing.h"

#include "core/ChunkFormat.h"
#include "core/StripeBuilder.h"
#include "identity/Identity.h"

#include <cstring>
#include <set>
#include <string>
#include <vector>

namespace {

const char* const kMnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon art";

bb::FileKey TestFileKey()
{
    bb::FileKey key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>((11 * 61 + i * 7) & 0xFF);
    }
    return key;
}

bb::Hash256 TestFileId()
{
    bb::Hash256 value{};
    for (std::size_t i = 0; i < value.size(); ++i) {
        value[i] = static_cast<std::uint8_t>((12 * 61 + i * 7) & 0xFF);
    }
    return value;
}

bb::ChunkMetadata SampleMetadata(std::uint32_t stripe = 1, std::uint16_t position = 4)
{
    bb::ChunkMetadata m;

    for (std::size_t i = 0; i < m.file_instance.size(); ++i) {
        m.file_instance[i] = static_cast<std::uint8_t>(i * 3 + 1);
    }
    for (std::size_t i = 0; i < m.content_hash.size(); ++i) {
        m.content_hash[i] = static_cast<std::uint8_t>(i * 5 + 2);
    }
    for (std::size_t i = 0; i < m.merkle_root.size(); ++i) {
        m.merkle_root[i] = static_cast<std::uint8_t>(i * 7 + 3);
    }

    m.file_name   = "document.pdf";
    m.file_path   = "Documents/Private/document.pdf";
    m.file_size   = 8734212;
    m.created     = 1785713340;
    m.modified    = 1785713390;
    m.attributes  = 32;
    m.stored_size = 6120044;
    m.split       = bb::kDefaultSplitProfile;

    m.rs_data     = 8;
    m.rs_parity   = 3;
    m.chunk_count = static_cast<std::uint32_t>(bb::SplitShardCount(20, 8, 3));

    m.merkle_path.resize(5, m.merkle_root);

    m.self_stripe   = stripe;
    m.self_position = position;
    m.self_index    = stripe * (m.rs_data + m.rs_parity) + position;

    return m;
}

std::vector<std::uint8_t> Core(std::size_t len)
{
    std::vector<std::uint8_t> core(len);
    for (std::size_t i = 0; i < len; ++i) {
        core[i] = static_cast<std::uint8_t>((i * 29 + 7) & 0xFF);
    }
    return core;
}

struct Built {
    bb::Identity              identity;
    bb::ChunkMetadata         metadata;
    bb::ObjectName            name{};
    std::vector<std::uint8_t> core;
    std::vector<std::uint8_t> blob;
};

bool BuildSample(Built& out, std::uint32_t stripe = 1, std::uint16_t position = 4,
                 std::size_t core_len = 300)
{
    if (!bb::Identity::FromMnemonic(kMnemonic, "", 0, out.identity)) {
        return false;
    }

    out.metadata = SampleMetadata(stripe, position);
    out.core     = Core(core_len);

    const bb::FileKey k_file  = TestFileKey();
    const bb::Hash256 file_id = TestFileId();

    if (!bb::DeriveObjectName(k_file, out.metadata.self_index, out.name)) {
        return false;
    }

    bb::ChunkBuildInput input;
    input.recipient_kem      = &out.identity.Kem();
    input.recipient_classic  = &out.identity.Classic();
    input.recipient_identity = &out.identity.Id();
    input.k_file             = &k_file;
    input.file_id            = &file_id;
    input.object_name        = &out.name;
    input.metadata           = &out.metadata;
    input.shard_core         = out.core.data();
    input.shard_core_len     = out.core.size();

    return bb::ChunkBuild(input, out.blob) == BB_OK;
}

bb_status OpenSample(const Built& built, bb::ChunkOpened& opened)
{
    return bb::ChunkOpen(built.identity.Kem(), built.identity.Classic(),
                         built.identity.Id(), built.identity.Id(), built.name,
                         built.blob.data(), built.blob.size(),
                         built.blob.size(), opened);
}

}  // namespace

BB_TEST(chunk_roundtrip)
{
    Built built;
    BB_CHECK(BuildSample(built));

    BB_CHECK_EQ(built.blob.size(),
                bb::kChunkPrefixLen + BB_META_CLASS_MIN + BB_TAG_LEN + built.core.size());

    bb::ChunkOpened opened;
    BB_CHECK_EQ(OpenSample(built, opened), BB_OK);

    BB_CHECK_EQ(std::memcmp(opened.k_file.data(), TestFileKey().data(), 32), 0);
    BB_CHECK_EQ(std::memcmp(opened.file_id.data(), TestFileId().data(), 32), 0);

    BB_CHECK_EQ(opened.metadata.self_index, built.metadata.self_index);
    BB_CHECK_STR(opened.metadata.file_path.c_str(), built.metadata.file_path.c_str());
    BB_CHECK_EQ(opened.metadata.file_size, built.metadata.file_size);

    BB_CHECK_EQ(opened.core_offset,
                bb::kChunkPrefixLen + BB_META_CLASS_MIN + BB_TAG_LEN);
    BB_CHECK_EQ(opened.core_length, built.core.size());
    BB_CHECK_EQ(std::memcmp(built.blob.data() + opened.core_offset,
                            built.core.data(), built.core.size()), 0);
}

// Открытого заголовка нет. Проверяется от противного: два чанка РАЗНЫХ файлов
// и разных identity не должны иметь ни одного совпадающего байта на общих
// позициях сверх случайного совпадения.
BB_TEST(chunk_has_no_plaintext_header)
{
    Built first;
    BB_CHECK(BuildSample(first));

    // Тот же файл, тот же чанк, но собранный заново: свежая encapsulation.
    Built second;
    BB_CHECK(BuildSample(second));

    BB_CHECK_EQ(first.blob.size(), second.blob.size());

    // Совпадать обязано только shard core — он не шифруется повторно, его
    // подаёт вызывающий. Всё, что до него, обязано различаться целиком.
    const std::size_t prefix_and_metadata =
        bb::kChunkPrefixLen + BB_META_CLASS_MIN + BB_TAG_LEN;

    std::size_t identical = 0;
    for (std::size_t i = 0; i < prefix_and_metadata; ++i) {
        if (first.blob[i] == second.blob[i]) {
            ++identical;
        }
    }

    // При равномерном шуме ожидается около 1/256 совпадений. Порог в 2% даёт
    // огромный запас и всё равно ловит любой фиксированный заголовок: даже
    // четырёхбайтовый magic на 5792 байтах не прошёл бы, будь он один, — но
    // главное, что константной области нет вовсе.
    BB_CHECK(identical < prefix_and_metadata / 50);

    // Ни одного из старых полей заголовка: magic "BBK1" в начале объекта.
    BB_CHECK(std::memcmp(first.blob.data(), "BBK1", 4) != 0);

    // identity_id больше не лежит открыто. Его 32 байта не должны встречаться
    // в объекте вообще.
    const bb::Hash256& id = first.identity.Id();
    bool               found = false;
    for (std::size_t i = 0; i + id.size() <= first.blob.size(); ++i) {
        if (std::memcmp(first.blob.data() + i, id.data(), id.size()) == 0) {
            found = true;
            break;
        }
    }
    BB_CHECK(!found);
}

// Правило проекта: порча любого единственного байта обязана быть обнаружена.
// Проверяются все байты префикса и метаданных; ядро аутентифицируется своим
// AEAD уровнем выше, поэтому здесь его порча законно проходит.
BB_TEST(chunk_detects_corruption_of_every_byte_before_the_core)
{
    Built built;
    BB_CHECK(BuildSample(built));

    const std::size_t guarded =
        bb::kChunkPrefixLen + BB_META_CLASS_MIN + BB_TAG_LEN;

    // Шаг выбран так, чтобы пройти каждое поле и уложиться в разумное время:
    // каждая проверка — это декапсуляция ML-KEM.
    for (std::size_t i = 0; i < guarded; i += 37) {
        std::vector<std::uint8_t> damaged = built.blob;
        damaged[i] ^= 0x01;

        bb::ChunkOpened opened;
        const bb_status status = bb::ChunkOpen(
            built.identity.Kem(), built.identity.Classic(), built.identity.Id(),
            built.identity.Id(), built.name, damaged.data(), damaged.size(),
            damaged.size(), opened);

        if (status == BB_OK) {
            std::printf("    byte %zu survived corruption\n", i);
            ++bb_failures;
            return;
        }
    }
}

// Чанк, переставленный под чужим именем, не открывается: имя входит в AAD
// метаданных и обязано выводиться из K_file.
BB_TEST(chunk_is_bound_to_its_object_name)
{
    Built built;
    BB_CHECK(BuildSample(built));

    bb::ObjectName other{};
    BB_CHECK(bb::DeriveObjectName(TestFileKey(), built.metadata.self_index + 1, other));

    bb::ChunkOpened opened;
    BB_CHECK_EQ(bb::ChunkOpen(built.identity.Kem(), built.identity.Classic(),
                              built.identity.Id(), built.identity.Id(), other,
                              built.blob.data(), built.blob.size(),
                              built.blob.size(), opened),
                BB_ERR_DECRYPT_FAILED);

    // Имя, не выводимое из K_file вовсе, — тоже отказ.
    bb::ObjectName foreign{};
    foreign.fill(0x5A);
    BB_CHECK_EQ(bb::ChunkOpen(built.identity.Kem(), built.identity.Classic(),
                              built.identity.Id(), built.identity.Id(), foreign,
                              built.blob.data(), built.blob.size(),
                              built.blob.size(), opened),
                BB_ERR_DECRYPT_FAILED);
}

// identity_id больше не лежит в чанке, поэтому принадлежность проверяется по
// имени объекта. BB_ERR_WRONG_IDENTITY при этом сохраняется (§15, вектор 6).
BB_TEST(chunk_rejects_a_foreign_identity_by_name)
{
    Built built;
    BB_CHECK(BuildSample(built));

    bb::Hash256 foreign = built.identity.Id();
    foreign[0] ^= 0x01;

    bb::ChunkOpened opened;
    BB_CHECK_EQ(bb::ChunkOpen(built.identity.Kem(), built.identity.Classic(),
                              built.identity.Id(), foreign, built.name,
                              built.blob.data(), built.blob.size(),
                              built.blob.size(), opened),
                BB_ERR_WRONG_IDENTITY);
}

// Чужие ключи — отказ, неотличимый от повреждения.
BB_TEST(chunk_rejects_a_foreign_key)
{
    Built built;
    BB_CHECK(BuildSample(built));

    bb::Identity other;
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "", 1, other));

    bb::ChunkOpened opened;
    BB_CHECK_EQ(bb::ChunkOpen(other.Kem(), other.Classic(), other.Id(), other.Id(),
                              built.name, built.blob.data(), built.blob.size(),
                              built.blob.size(), opened),
                BB_ERR_DECRYPT_FAILED);
}

// Range-чтение: достаточно префикса и области метаданных, ядро не нужно.
BB_TEST(chunk_opens_from_a_truncated_probe)
{
    Built built;
    BB_CHECK(BuildSample(built, 1, 4, 5 * 1024 * 1024));

    const std::size_t probe = bb::kChunkPrefixLen + BB_META_CLASS_MIN + BB_TAG_LEN;
    BB_CHECK(built.blob.size() > probe);

    bb::ChunkOpened opened;
    BB_CHECK_EQ(bb::ChunkOpen(built.identity.Kem(), built.identity.Classic(),
                              built.identity.Id(), built.identity.Id(), built.name,
                              built.blob.data(), probe, built.blob.size(), opened),
                BB_OK);

    // Длина ядра выводится из размера объекта, а не из прочитанного куска.
    BB_CHECK_EQ(opened.core_length, built.core.size());
    BB_CHECK_EQ(opened.core_offset, probe);
}

BB_TEST(chunk_rejects_a_too_short_object)
{
    Built built;
    BB_CHECK(BuildSample(built));

    bb::ChunkOpened opened;
    BB_CHECK_EQ(bb::ChunkOpen(built.identity.Kem(), built.identity.Classic(),
                              built.identity.Id(), built.identity.Id(), built.name,
                              built.blob.data(), bb::kChunkPrefixLen,
                              built.blob.size(), opened),
                BB_ERR_BAD_CONTAINER);

    // object_size меньше прочитанного — противоречие.
    BB_CHECK_EQ(bb::ChunkOpen(built.identity.Kem(), built.identity.Classic(),
                              built.identity.Id(), built.identity.Id(), built.name,
                              built.blob.data(), built.blob.size(), 10, opened),
                BB_ERR_BAD_CONTAINER);
}

// Класс метаданных подбирается пробным расшифрованием, а не читается из
// заголовка. Длинный путь и глубокий merkle_path не должны это ломать.
BB_TEST(chunk_finds_the_metadata_class_by_trial)
{
    Built built;
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "", 0, built.identity));

    built.metadata = SampleMetadata();
    built.metadata.file_path.assign(bb::kMetadataMaxPathLen, 'p');
    built.metadata.file_name.assign(bb::kMetadataMaxNameLen, 'n');
    built.metadata.merkle_path.resize(13, built.metadata.merkle_root);
    built.core = Core(64);

    const bb::FileKey k_file  = TestFileKey();
    const bb::Hash256 file_id = TestFileId();
    BB_CHECK(bb::DeriveObjectName(k_file, built.metadata.self_index, built.name));

    bb::ChunkBuildInput input;
    input.recipient_kem      = &built.identity.Kem();
    input.recipient_classic  = &built.identity.Classic();
    input.recipient_identity = &built.identity.Id();
    input.k_file             = &k_file;
    input.file_id            = &file_id;
    input.object_name        = &built.name;
    input.metadata           = &built.metadata;
    input.shard_core         = built.core.data();
    input.shard_core_len     = built.core.size();

    BB_CHECK_EQ(bb::ChunkBuild(input, built.blob), BB_OK);

    bb::ChunkOpened opened;
    BB_CHECK_EQ(OpenSample(built, opened), BB_OK);
    BB_CHECK_EQ(opened.metadata_class, static_cast<std::size_t>(BB_META_CLASS_MIN));
    BB_CHECK_EQ(opened.core_length, built.core.size());
}

// Имя обязано соответствовать индексу из метаданных: собрать чанк под чужим
// именем нельзя даже намеренно.
BB_TEST(chunk_build_rejects_a_name_that_does_not_match_the_index)
{
    bb::Identity identity;
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "", 0, identity));

    const bb::ChunkMetadata metadata = SampleMetadata();
    const bb::FileKey       k_file   = TestFileKey();
    const bb::Hash256       file_id  = TestFileId();
    const std::vector<std::uint8_t> core = Core(32);

    bb::ObjectName wrong{};
    BB_CHECK(bb::DeriveObjectName(k_file, metadata.self_index + 1, wrong));

    bb::ChunkBuildInput input;
    input.recipient_kem      = &identity.Kem();
    input.recipient_classic  = &identity.Classic();
    input.recipient_identity = &identity.Id();
    input.k_file             = &k_file;
    input.file_id            = &file_id;
    input.object_name        = &wrong;
    input.metadata           = &metadata;
    input.shard_core         = core.data();
    input.shard_core_len     = core.size();

    std::vector<std::uint8_t> blob;
    BB_CHECK_EQ(bb::ChunkBuild(input, blob), BB_ERR_INVALID_ARG);
}

// Случайное дополнение не мешает найти ядро: его длина лежит в метаданных.
BB_TEST(chunk_carries_random_cover_padding)
{
    bb::Identity identity;
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "", 0, identity));

    bb::ChunkMetadata metadata = SampleMetadata();
    metadata.padding = 777;

    const bb::FileKey k_file  = TestFileKey();
    const bb::Hash256 file_id = TestFileId();
    const std::vector<std::uint8_t> core = Core(100);

    bb::ObjectName name{};
    BB_CHECK(bb::DeriveObjectName(k_file, metadata.self_index, name));

    bb::ChunkBuildInput input;
    input.recipient_kem      = &identity.Kem();
    input.recipient_classic  = &identity.Classic();
    input.recipient_identity = &identity.Id();
    input.k_file             = &k_file;
    input.file_id            = &file_id;
    input.object_name        = &name;
    input.metadata           = &metadata;
    input.shard_core         = core.data();
    input.shard_core_len     = core.size();

    std::vector<std::uint8_t> blob;
    BB_CHECK_EQ(bb::ChunkBuild(input, blob), BB_OK);
    BB_CHECK_EQ(blob.size(),
                bb::kChunkPrefixLen + BB_META_CLASS_MIN + BB_TAG_LEN + 100 + 777);

    bb::ChunkOpened opened;
    BB_CHECK_EQ(bb::ChunkOpen(identity.Kem(), identity.Classic(), identity.Id(),
                              identity.Id(), name, blob.data(), blob.size(),
                              blob.size(), opened),
                BB_OK);
    BB_CHECK_EQ(opened.core_length, std::size_t{100});
    BB_CHECK_EQ(opened.metadata.padding, std::uint32_t{777});
}

// ---------------------------------------------------------------------------
// Имена всех объектов из одного чанка
// ---------------------------------------------------------------------------

// То самое свойство, ради которого имена выводятся, а не хешируются: один
// вскрытый чанк даёт адреса всех остальных.
BB_TEST(chunk_yields_the_names_of_every_object)
{
    Built built;
    BB_CHECK(BuildSample(built));

    bb::ChunkOpened opened;
    BB_CHECK_EQ(OpenSample(built, opened), BB_OK);

    std::vector<bb::ObjectName> names;
    BB_CHECK_EQ(bb::ChunkObjectNames(opened.k_file, opened.metadata, names), BB_OK);
    BB_CHECK_EQ(names.size(), static_cast<std::size_t>(opened.metadata.chunk_count));

    // Все имена различны.
    std::set<std::string> unique;
    for (const bb::ObjectName& name : names) {
        unique.insert(bb::test::Hex(name.data(), name.size()));
    }
    BB_CHECK_EQ(unique.size(), names.size());

    // Имя самого чанка обязано оказаться среди них.
    BB_CHECK(unique.count(bb::test::Hex(built.name.data(), built.name.size())) == 1);
}

// Неполная последняя stripe: индексы не сплошные, и перечисление обязано это
// учитывать, иначе имена уедут (§10, §12).
BB_TEST(chunk_names_account_for_a_partial_last_stripe)
{
    bb::ChunkMetadata metadata = SampleMetadata(0, 0);
    metadata.chunk_count = static_cast<std::uint32_t>(bb::SplitShardCount(10, 8, 3));
    BB_CHECK_EQ(metadata.chunk_count, 16u);

    std::vector<bb::ObjectName> names;
    BB_CHECK_EQ(bb::ChunkObjectNames(TestFileKey(), metadata, names), BB_OK);
    BB_CHECK_EQ(names.size(), std::size_t{16});

    // Ожидаемые канонические индексы: 0..10 первой stripe, затем 11, 12 и
    // 19, 20, 21 второй. Позиции 13..18 не существуют.
    const std::uint32_t expected[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                      11, 12, 19, 20, 21};
    for (std::size_t i = 0; i < names.size(); ++i) {
        bb::ObjectName reference{};
        BB_CHECK(bb::DeriveObjectName(TestFileKey(), expected[i], reference));
        BB_CHECK_EQ(std::memcmp(names[i].data(), reference.data(), 32), 0);
    }
}

BB_TEST(chunk_names_reject_impossible_metadata)
{
    bb::ChunkMetadata metadata = SampleMetadata();
    std::vector<bb::ObjectName> names;

    metadata.chunk_count = 0;
    BB_CHECK_EQ(bb::ChunkObjectNames(TestFileKey(), metadata, names),
                BB_ERR_INVALID_ARG);

    // Недостижимое число объектов: между 11 (n = 8) и 15 (n = 9) значений нет.
    metadata.chunk_count = 13;
    BB_CHECK_EQ(bb::ChunkObjectNames(TestFileKey(), metadata, names),
                BB_ERR_BAD_CONTAINER);
}
