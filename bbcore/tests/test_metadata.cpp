// Метаданные чанка и CBOR под ними — §13.
//
// Здесь сходятся две задачи. Первая — round-trip: то, что записано, обязано
// прочитаться побайтово тем же. Вторая, более важная, — разбор недоверенного
// ввода: метаданные приходят из чужого хранилища, и всё, что не является
// канонической формой, должно быть отвергнуто, а не разобрано «как получится».

#include "Testing.h"

#include "core/MetadataCodec.h"
#include "util/Cbor.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

bb::ChunkMetadata SampleMetadata()
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

    m.file_name  = "document.pdf";
    m.file_path  = "Documents/Private/document.pdf";
    m.file_size  = 8734212;
    m.created    = 1785713340;
    m.modified   = 1785713390;
    m.attributes = 32;

    m.transform_id = {0, 0, 0, 0};
    m.stored_size  = 6120044;
    m.split        = bb::kDefaultSplitProfile;

    m.rs_data     = 8;
    m.rs_parity   = 3;
    m.chunk_count = 33;

    for (std::size_t node = 0; node < 5; ++node) {
        bb::Hash256 value{};
        for (std::size_t i = 0; i < value.size(); ++i) {
            value[i] = static_cast<std::uint8_t>(node * 31 + i);
        }
        m.merkle_path.push_back(value);
    }

    m.self_stripe   = 1;
    m.self_position = 4;
    m.self_index    = m.self_stripe * (m.rs_data + m.rs_parity) + m.self_position;

    return m;
}

bool Same(const bb::ChunkMetadata& a, const bb::ChunkMetadata& b)
{
    if (a.version != b.version || a.file_name != b.file_name
     || a.file_path != b.file_path || a.file_size != b.file_size
     || a.created != b.created || a.modified != b.modified
     || a.attributes != b.attributes || a.stored_size != b.stored_size
     || a.rs_data != b.rs_data || a.rs_parity != b.rs_parity
     || a.chunk_count != b.chunk_count || a.self_index != b.self_index
     || a.self_stripe != b.self_stripe || a.self_position != b.self_position) {
        return false;
    }
    if (a.split.min != b.split.min || a.split.avg != b.split.avg
     || a.split.max != b.split.max || a.split.align != b.split.align) {
        return false;
    }
    if (a.file_instance != b.file_instance || a.content_hash != b.content_hash
     || a.transform_id != b.transform_id || a.merkle_root != b.merkle_root) {
        return false;
    }
    return a.merkle_path == b.merkle_path;
}

std::vector<std::uint8_t> Encoded(const bb::ChunkMetadata& m)
{
    std::vector<std::uint8_t> out;
    if (bb::MetadataEncode(m, out) != BB_OK) {
        out.clear();
    }
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// CBOR
// ---------------------------------------------------------------------------

BB_TEST(cbor_writes_minimal_length_headers)
{
    struct Case {
        std::uint64_t value;
        const char*   expected_hex;
    };

    const Case cases[] = {
        {0,          "00"},
        {1,          "01"},
        {23,         "17"},
        {24,         "1818"},
        {255,        "18ff"},
        {256,        "190100"},
        {65535,      "19ffff"},
        {65536,      "1a00010000"},
        {4294967295, "1affffffff"},
        {4294967296, "1b0000000100000000"},
    };

    for (const Case& c : cases) {
        bb::CborWriter writer;
        writer.Uint(c.value);
        BB_CHECK_STR(bb::test::Hex(writer.Buffer().data(),
                                   writer.Buffer().size()).c_str(),
                     c.expected_hex);
    }
}

BB_TEST(cbor_writes_negative_integers)
{
    struct Case {
        std::int64_t value;
        const char*  expected_hex;
    };

    const Case cases[] = {
        {-1,   "20"},
        {-24,  "37"},
        {-25,  "3818"},
        {-256, "38ff"},
        {-257, "390100"},
    };

    for (const Case& c : cases) {
        bb::CborWriter writer;
        writer.Int(c.value);
        BB_CHECK_STR(bb::test::Hex(writer.Buffer().data(),
                                   writer.Buffer().size()).c_str(),
                     c.expected_hex);

        bb::CborReader reader(writer.Buffer().data(), writer.Buffer().size());
        std::int64_t   back = 0;
        BB_CHECK(reader.ReadInt(back));
        BB_CHECK_EQ(back, c.value);
    }
}

// Одно и то же число обязано иметь одно представление, иначе у метаданных с
// одинаковым содержимым было бы несколько кодировок.
BB_TEST(cbor_rejects_non_minimal_headers)
{
    const std::uint8_t one_byte[]  = {0x18, 0x01};              // 1 через uint8
    const std::uint8_t two_byte[]  = {0x19, 0x00, 0x01};        // 1 через uint16
    const std::uint8_t four_byte[] = {0x1a, 0, 0, 0, 0x01};     // 1 через uint32
    const std::uint8_t boundary[]  = {0x19, 0x00, 0xff};        // 255 через uint16

    for (const auto& blob : {std::vector<std::uint8_t>(one_byte, one_byte + 2),
                             std::vector<std::uint8_t>(two_byte, two_byte + 3),
                             std::vector<std::uint8_t>(four_byte, four_byte + 5),
                             std::vector<std::uint8_t>(boundary, boundary + 3)}) {
        bb::CborReader reader(blob.data(), blob.size());
        std::uint64_t  value = 0;
        BB_CHECK(!reader.ReadUint(value));
    }

    // А минимальные формы тех же чисел проходят.
    const std::uint8_t minimal_255[] = {0x18, 0xff};
    bb::CborReader     reader(minimal_255, sizeof minimal_255);
    std::uint64_t      value = 0;
    BB_CHECK(reader.ReadUint(value));
    BB_CHECK_EQ(value, std::uint64_t{255});
}

// Неопределённая длина, теги, float и simple values в схеме §13 не встречаются.
// Принимать то, чего не пишешь, значит расширять поверхность разбора зря.
BB_TEST(cbor_rejects_types_outside_the_schema)
{
    const std::uint8_t indefinite_array[] = {0x9f, 0x01, 0xff};
    const std::uint8_t indefinite_text[]  = {0x7f, 0x61, 0x61, 0xff};
    const std::uint8_t reserved[]         = {0x1c};
    const std::uint8_t tagged[]           = {0xc1, 0x01};
    const std::uint8_t floating[]         = {0xfa, 0x3f, 0x80, 0x00, 0x00};
    const std::uint8_t simple_true[]      = {0xf5};

    {
        bb::CborReader reader(indefinite_array, sizeof indefinite_array);
        std::size_t    count = 0;
        BB_CHECK(!reader.ReadArrayHeader(count, 16));
    }
    {
        bb::CborReader   reader(indefinite_text, sizeof indefinite_text);
        std::string_view text;
        BB_CHECK(!reader.ReadText(text, 16));
    }
    for (const auto& blob : {std::vector<std::uint8_t>(reserved, reserved + 1),
                             std::vector<std::uint8_t>(tagged, tagged + 2),
                             std::vector<std::uint8_t>(floating, floating + 5),
                             std::vector<std::uint8_t>(simple_true, simple_true + 1)}) {
        bb::CborReader reader(blob.data(), blob.size());
        std::uint64_t  value = 0;
        std::int64_t   signed_value = 0;
        BB_CHECK(!reader.ReadUint(value));

        bb::CborReader again(blob.data(), blob.size());
        BB_CHECK(!again.ReadInt(signed_value));
    }
}

// Длина приходит из недоверенных данных и обязана проверяться до обращения к
// буферу, а не после.
BB_TEST(cbor_rejects_lengths_beyond_the_buffer)
{
    const std::uint8_t long_text[]  = {0x78, 0x40, 'a', 'b'};   // заявлено 64 байта
    const std::uint8_t long_bytes[] = {0x58, 0x20, 0x00};       // заявлено 32 байта
    const std::uint8_t huge_text[]  = {0x7b, 0xff, 0xff, 0xff, 0xff,
                                       0xff, 0xff, 0xff, 0xff};

    {
        bb::CborReader   reader(long_text, sizeof long_text);
        std::string_view text;
        BB_CHECK(!reader.ReadText(text, 1024));
    }
    {
        bb::CborReader reader(long_bytes, sizeof long_bytes);
        std::uint8_t   buffer[32] = {};
        BB_CHECK(!reader.ReadBytes(buffer, sizeof buffer));
    }
    {
        bb::CborReader   reader(huge_text, sizeof huge_text);
        std::string_view text;
        BB_CHECK(!reader.ReadText(text, 1024));
    }
}

// Порядок ключей — часть канонической формы. Строгое возрастание заодно
// запрещает дубликаты, а с ними и вопрос, какое из двух значений верное.
BB_TEST(cbor_enforces_canonical_key_order)
{
    bb::CborWriter writer;
    writer.Text("v");
    writer.Text("rs");
    writer.Text("file");
    writer.Text("self");

    bb::CborReader   reader(writer.Buffer().data(), writer.Buffer().size());
    std::string_view key;
    std::string_view previous;

    BB_CHECK(reader.ReadMapKey(key, previous)); previous = key;
    BB_CHECK(reader.ReadMapKey(key, previous)); previous = key;
    BB_CHECK(reader.ReadMapKey(key, previous)); previous = key;
    BB_CHECK(reader.ReadMapKey(key, previous));

    // Тот же ключ второй раз, ключ не по порядку и более короткий после
    // длинного — всё три отказ.
    bb::CborWriter bad;
    bad.Text("file");
    bad.Text("file");
    bb::CborReader duplicate(bad.Buffer().data(), bad.Buffer().size());
    BB_CHECK(duplicate.ReadMapKey(key, std::string_view()));
    BB_CHECK(!duplicate.ReadMapKey(key, std::string_view("file")));

    bb::CborWriter reversed;
    reversed.Text("self");
    reversed.Text("file");
    bb::CborReader out_of_order(reversed.Buffer().data(), reversed.Buffer().size());
    BB_CHECK(out_of_order.ReadMapKey(key, std::string_view()));
    BB_CHECK(!out_of_order.ReadMapKey(key, std::string_view("self")));

    bb::CborWriter shorter;
    shorter.Text("v");
    bb::CborReader after_long(shorter.Buffer().data(), shorter.Buffer().size());
    BB_CHECK(!after_long.ReadMapKey(key, std::string_view("file")));
}

// ---------------------------------------------------------------------------
// Метаданные
// ---------------------------------------------------------------------------

BB_TEST(metadata_roundtrip)
{
    const bb::ChunkMetadata original = SampleMetadata();

    std::vector<std::uint8_t> plaintext;
    BB_CHECK_EQ(bb::MetadataEncode(original, plaintext), BB_OK);
    BB_CHECK_EQ(plaintext.size(), static_cast<std::size_t>(BB_META_CLASS_MIN));

    bb::ChunkMetadata decoded;
    BB_CHECK_EQ(bb::MetadataDecode(plaintext.data(), plaintext.size(), decoded), BB_OK);
    BB_CHECK(Same(original, decoded));
}

// Метаданные — детерминированная функция своего содержимого: два кодирования
// обязаны дать одинаковые байты, иначе дедупликация по чанкам развалилась бы.
BB_TEST(metadata_encoding_is_deterministic)
{
    const std::vector<std::uint8_t> first  = Encoded(SampleMetadata());
    const std::vector<std::uint8_t> second = Encoded(SampleMetadata());

    BB_CHECK(!first.empty());
    BB_CHECK_EQ(first.size(), second.size());
    BB_CHECK_EQ(std::memcmp(first.data(), second.data(), first.size()), 0);
}

// Дополнение до класса — единственное, что мешает хранилищу оценить по
// len_metadata длину пути и число чанков файла.
BB_TEST(metadata_is_padded_to_a_size_class)
{
    bb::ChunkMetadata compact = SampleMetadata();
    compact.file_path = "a";
    compact.file_name = "a";
    compact.merkle_path.clear();

    bb::ChunkMetadata verbose = SampleMetadata();
    verbose.file_path.assign(bb::kMetadataMaxPathLen, 'x');
    verbose.merkle_path.resize(13, verbose.merkle_root);

    const std::vector<std::uint8_t> small = Encoded(compact);
    const std::vector<std::uint8_t> large = Encoded(verbose);

    BB_CHECK(!small.empty());
    BB_CHECK(!large.empty());

    // Разница в длине пути и в merkle_path снаружи не видна.
    BB_CHECK_EQ(small.size(), static_cast<std::size_t>(BB_META_CLASS_MIN));
    BB_CHECK_EQ(large.size(), static_cast<std::size_t>(BB_META_CLASS_MIN));

    // Хвост — нули.
    const std::uint32_t payload =
        static_cast<std::uint32_t>(small[0]) << 24 | static_cast<std::uint32_t>(small[1]) << 16
      | static_cast<std::uint32_t>(small[2]) << 8  | static_cast<std::uint32_t>(small[3]);
    for (std::size_t i = 4 + payload; i < small.size(); ++i) {
        BB_CHECK_EQ(static_cast<int>(small[i]), 0);
    }
}

BB_TEST(metadata_size_classes)
{
    std::size_t klass = 0;

    BB_CHECK(bb::MetadataSizeClass(0, &klass));
    BB_CHECK_EQ(klass, static_cast<std::size_t>(BB_META_CLASS_MIN));

    BB_CHECK(bb::MetadataSizeClass(BB_META_CLASS_MIN - 4, &klass));
    BB_CHECK_EQ(klass, static_cast<std::size_t>(BB_META_CLASS_MIN));

    BB_CHECK(bb::MetadataSizeClass(BB_META_CLASS_MIN - 3, &klass));
    BB_CHECK_EQ(klass, static_cast<std::size_t>(BB_META_CLASS_MID));

    BB_CHECK(bb::MetadataSizeClass(BB_META_CLASS_MID, &klass));
    BB_CHECK_EQ(klass, static_cast<std::size_t>(BB_META_CLASS_MAX));

    BB_CHECK(!bb::MetadataSizeClass(BB_META_CLASS_MAX, &klass));
    BB_CHECK(!bb::MetadataSizeClass(0, nullptr));
}

// Максимальный merkle_path при 8192 чанках плюс длинный путь обязаны
// уложиться в младший класс — иначе §13 обещал бы «4 KiB покрывает
// подавляющее большинство случаев» напрасно.
BB_TEST(metadata_worst_case_fits_the_smallest_class)
{
    bb::ChunkMetadata m = SampleMetadata();
    m.file_path.assign(bb::kMetadataMaxPathLen, 'p');
    m.file_name.assign(bb::kMetadataMaxNameLen, 'n');
    m.merkle_path.resize(13, m.merkle_root);
    m.chunk_count = 8192;

    const std::vector<std::uint8_t> plaintext = Encoded(m);
    BB_CHECK(!plaintext.empty());
    BB_CHECK_EQ(plaintext.size(), static_cast<std::size_t>(BB_META_CLASS_MIN));
}

// ---------------------------------------------------------------------------
// Недоверенный ввод
// ---------------------------------------------------------------------------

BB_TEST(metadata_rejects_wrong_container_length)
{
    std::vector<std::uint8_t> plaintext = Encoded(SampleMetadata());
    BB_CHECK(!plaintext.empty());

    bb::ChunkMetadata decoded;
    BB_CHECK_EQ(bb::MetadataDecode(plaintext.data(), plaintext.size() - 1, decoded),
                BB_ERR_BAD_CONTAINER);
    BB_CHECK_EQ(bb::MetadataDecode(plaintext.data(), 0, decoded),
                BB_ERR_BAD_CONTAINER);
    BB_CHECK_EQ(bb::MetadataDecode(nullptr, plaintext.size(), decoded),
                BB_ERR_INVALID_ARG);
}

BB_TEST(metadata_rejects_a_payload_length_past_the_buffer)
{
    std::vector<std::uint8_t> plaintext = Encoded(SampleMetadata());
    BB_CHECK(!plaintext.empty());

    plaintext[0] = 0xFF;
    plaintext[1] = 0xFF;

    bb::ChunkMetadata decoded;
    BB_CHECK_EQ(bb::MetadataDecode(plaintext.data(), plaintext.size(), decoded),
                BB_ERR_BAD_CONTAINER);
}

// Мусор в дополнении — скрытый канал. Он под AEAD, но отвергнуть его стоит
// одного прохода.
BB_TEST(metadata_rejects_non_zero_padding)
{
    std::vector<std::uint8_t> plaintext = Encoded(SampleMetadata());
    BB_CHECK(!plaintext.empty());

    plaintext[plaintext.size() - 1] = 0x01;

    bb::ChunkMetadata decoded;
    BB_CHECK_EQ(bb::MetadataDecode(plaintext.data(), plaintext.size(), decoded),
                BB_ERR_BAD_CONTAINER);
}

// Правило проекта: порча любого байта обязана быть обнаружена. В полезной
// части это обеспечивает строгий разбор, в хвосте — проверка нулей.
BB_TEST(metadata_detects_corruption_of_every_byte)
{
    const std::vector<std::uint8_t> original = Encoded(SampleMetadata());
    BB_CHECK(!original.empty());

    for (std::size_t i = 0; i < original.size(); ++i) {
        std::vector<std::uint8_t> damaged = original;
        damaged[i] ^= 0x01;

        bb::ChunkMetadata decoded;
        const bb_status   status =
            bb::MetadataDecode(damaged.data(), damaged.size(), decoded);

        // Либо разбор отверг байт, либо значение изменилось — молча вернуть
        // исходные метаданные нельзя.
        if (status == BB_OK && Same(SampleMetadata(), decoded)) {
            std::printf("    byte %zu survived corruption unnoticed\n", i);
            ++bb_failures;
            return;
        }
    }
}

// §12 задаёт индекс как функцию stripe и position. Расхождение означало бы
// чанк, чьё имя не соответствует его месту в раскладке.
BB_TEST(metadata_rejects_an_inconsistent_self_index)
{
    bb::ChunkMetadata m = SampleMetadata();
    m.self_index += 1;

    std::vector<std::uint8_t> plaintext;
    BB_CHECK_EQ(bb::MetadataEncode(m, plaintext), BB_ERR_INVALID_ARG);

    m = SampleMetadata();
    m.self_position = static_cast<std::uint16_t>(m.rs_data + m.rs_parity);
    BB_CHECK_EQ(bb::MetadataEncode(m, plaintext), BB_ERR_INVALID_ARG);
}

BB_TEST(metadata_rejects_impossible_parameters)
{
    std::vector<std::uint8_t> plaintext;

    bb::ChunkMetadata zero_rs = SampleMetadata();
    zero_rs.rs_data = 0;
    BB_CHECK_EQ(bb::MetadataEncode(zero_rs, plaintext), BB_ERR_INVALID_ARG);

    bb::ChunkMetadata too_many = SampleMetadata();
    too_many.chunk_count = BB_MAX_CHUNKS + 1;
    BB_CHECK_EQ(bb::MetadataEncode(too_many, plaintext), BB_ERR_INVALID_ARG);

    bb::ChunkMetadata bad_split = SampleMetadata();
    bad_split.split.min = bad_split.split.max + 1;
    BB_CHECK_EQ(bb::MetadataEncode(bad_split, plaintext), BB_ERR_INVALID_ARG);

    bb::ChunkMetadata bad_version = SampleMetadata();
    bad_version.version = 2;
    BB_CHECK_EQ(bb::MetadataEncode(bad_version, plaintext), BB_ERR_INVALID_ARG);
}

BB_TEST(metadata_rejects_oversized_fields)
{
    std::vector<std::uint8_t> plaintext;

    bb::ChunkMetadata long_path = SampleMetadata();
    long_path.file_path.assign(bb::kMetadataMaxPathLen + 1, 'x');
    BB_CHECK_EQ(bb::MetadataEncode(long_path, plaintext), BB_ERR_INVALID_ARG);

    bb::ChunkMetadata long_name = SampleMetadata();
    long_name.file_name.assign(bb::kMetadataMaxNameLen + 1, 'x');
    BB_CHECK_EQ(bb::MetadataEncode(long_name, plaintext), BB_ERR_INVALID_ARG);

    bb::ChunkMetadata deep = SampleMetadata();
    deep.merkle_path.resize(bb::kMetadataMaxPathNodes + 1, deep.merkle_root);
    BB_CHECK_EQ(bb::MetadataEncode(deep, plaintext), BB_ERR_INVALID_ARG);
}

// Отрицательные метки времени законны: файл может быть датирован до 1970 года,
// и превратить это в огромное положительное число значило бы соврать при
// восстановлении.
BB_TEST(metadata_carries_negative_timestamps)
{
    bb::ChunkMetadata m = SampleMetadata();
    m.created  = -86400;
    m.modified = -1;

    std::vector<std::uint8_t> plaintext;
    BB_CHECK_EQ(bb::MetadataEncode(m, plaintext), BB_OK);

    bb::ChunkMetadata decoded;
    BB_CHECK_EQ(bb::MetadataDecode(plaintext.data(), plaintext.size(), decoded), BB_OK);
    BB_CHECK_EQ(decoded.created, std::int64_t{-86400});
    BB_CHECK_EQ(decoded.modified, std::int64_t{-1});
}

// Пустой файл — законный случай: один чанк, пустой merkle_path, нулевой размер.
BB_TEST(metadata_handles_an_empty_file)
{
    bb::ChunkMetadata m = SampleMetadata();
    m.file_size   = 0;
    m.stored_size = 0;
    m.chunk_count = 4;
    m.merkle_path.clear();
    m.self_stripe   = 0;
    m.self_position = 0;
    m.self_index    = 0;

    std::vector<std::uint8_t> plaintext;
    BB_CHECK_EQ(bb::MetadataEncode(m, plaintext), BB_OK);

    bb::ChunkMetadata decoded;
    BB_CHECK_EQ(bb::MetadataDecode(plaintext.data(), plaintext.size(), decoded), BB_OK);
    BB_CHECK(Same(m, decoded));
    BB_CHECK(decoded.merkle_path.empty());
}

// Нулевой байт внутри пути превратил бы строку в C ABI в обрезок, и файл
// восстановился бы не туда.
BB_TEST(metadata_rejects_embedded_nul_in_paths)
{
    bb::ChunkMetadata m = SampleMetadata();
    m.file_path = std::string("Documents/a\0b/file.txt", 22);

    std::vector<std::uint8_t> plaintext;
    BB_CHECK_EQ(bb::MetadataEncode(m, plaintext), BB_OK);

    bb::ChunkMetadata decoded;
    BB_CHECK_EQ(bb::MetadataDecode(plaintext.data(), plaintext.size(), decoded),
                BB_ERR_BAD_CONTAINER);
}
