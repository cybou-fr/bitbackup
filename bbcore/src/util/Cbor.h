// Минимальный CBOR (RFC 8949) в канонической форме.
//
// Готовой библиотеки здесь нет намеренно. Формату нужна ровно одна схема —
// метаданные чанка (§13), — зато нужна строгость: разбор идёт над данными,
// пришедшими из чужого хранилища, и всё, что не является канонической формой,
// обязано быть отвергнуто, а не разобрано «как получится».
//
// Поддерживаются только те типы, которые встречаются в §13: целые со знаком и
// без, байтовые и текстовые строки, массивы и словари определённой длины.
// Неопределённая длина, теги, плавающая точка и simple values отвергаются —
// в схеме их нет, а принимать то, чего не пишешь, значит расширять поверхность
// разбора без причины.
//
// Канонические требования, которые проверяет читатель:
//
//   * заголовок минимальной длины — 1 не кодируется как 0x1b 00…01;
//   * ключи словаря строго возрастают в лексикографическом порядке своего
//     кодированного представления (RFC 8949 §4.2.1), откуда заодно следует
//     отсутствие дубликатов;
//   * длина не выходит за пределы буфера — проверяется до всякого выделения.
//
// Писатель выдаёт заголовки минимальной длины, а порядок ключей на нём: он
// пишет их в том порядке, в каком его вызвали. Ошибка порядка ловится
// round-trip тестом через строгий читатель.

#ifndef BBCORE_UTIL_CBOR_H
#define BBCORE_UTIL_CBOR_H

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace bb {

class CborWriter {
public:
    void Uint(std::uint64_t value);
    void Int(std::int64_t value);
    void Bytes(const void* data, std::size_t len);
    void Text(std::string_view text);
    void ArrayHeader(std::size_t count);
    void MapHeader(std::size_t count);

    const std::vector<std::uint8_t>& Buffer() const { return buffer_; }
    std::vector<std::uint8_t>&       Buffer() { return buffer_; }

private:
    void Head(std::uint8_t major, std::uint64_t value);

    std::vector<std::uint8_t> buffer_;
};

class CborReader {
public:
    CborReader(const std::uint8_t* data, std::size_t len)
        : data_(data), size_(len) {}

    bool AtEnd() const { return offset_ >= size_; }
    std::size_t Offset() const { return offset_; }

    bool ReadUint(std::uint64_t& out);
    bool ReadInt(std::int64_t& out);

    /// Байтовая строка ровно ожидаемой длины — все они в §13 фиксированы.
    bool ReadBytes(std::uint8_t* out, std::size_t expected_len);

    /// Текст с потолком длины. Указывает внутрь исходного буфера.
    bool ReadText(std::string_view& out, std::size_t max_len);

    bool ReadArrayHeader(std::size_t& out_count, std::size_t max_count);
    bool ReadMapHeader(std::size_t& out_count, std::size_t max_count);

    /// Очередной ключ словаря. Проверяет строгое возрастание относительно
    /// предыдущего ключа того же словаря — отсюда и запрет дубликатов.
    bool ReadMapKey(std::string_view& out, std::string_view previous);

private:
    bool ReadHead(std::uint8_t& out_major, std::uint64_t& out_value);

    const std::uint8_t* data_   = nullptr;
    std::size_t         size_   = 0;
    std::size_t         offset_ = 0;
};

}  // namespace bb

#endif  // BBCORE_UTIL_CBOR_H
