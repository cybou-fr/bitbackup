// Векторы AES-256-GCM-SIV — RFC 8452, приложение C.2, плюс проверки переноса
// счётчика из того же документа. Взяты из
// test/recipes/30-test_evp_data/evpciph_aes_gcm_siv.txt в исходниках OpenSSL,
// где секция помечена "Title = RFC8452 AES-GCM-SIV".
//
// Оговорка о происхождении. Обёртка над OpenSSL проверяется значениями из
// поставки OpenSSL — независимой реализации здесь нет. Сами значения родом из
// RFC, поэтому вектор ловит ошибку в порядке вызовов, в работе с AAD и в
// раскладке ciphertext || tag, но подтвердить чужой шифр он, разумеется, не
// может.
//
// Все векторы записаны как одно сообщение: наш формат шифрует shard core и
// метаданные целиком, потоковой обработки в bbk/1 нет.

#include "Testing.h"

#include "crypto/Aead.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

struct Vector {
    const char* key_hex;
    const char* nonce_hex;
    const char* aad_hex;
    const char* plaintext_hex;
    const char* ciphertext_hex;
    const char* tag_hex;
};

const Vector kVectors[] = {
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "",
     "",
     "",
     "07f5f4169bbf55a8400cd47ea6fd400f"},
    {"e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200",
     "e0eaf5284d884a0e77d31646",
     "",
     "",
     "",
     "169fbb2fbf389a995f6390af22228a62"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "",
     "0100000000000000",
     "c2ef328e5c71c83b",
     "843122130f7364b761e0b97427e3df28"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "",
     "010000000000000000000000",
     "9aab2aeb3faa0a34aea8e2b1",
     "8ca50da9ae6559e48fd10f6e5c9ca17e"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "",
     "01000000000000000000000000000000",
     "85a01b63025ba19b7fd3ddfc033b3e76",
     "c9eac6fa700942702e90862383c6c366"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "",
     "0100000000000000000000000000000002000000000000000000000000000000",
     "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027f",
     "e819e63abcd020b006a976397632eb5d"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "",
     "0100000000000000000000000000000002000000000000000000000000000000"
         "03000000000000000000000000000000",
     "c00d121893a9fa603f48ccc1ca3c57ce7499245ea0046db16c53c7c66fe717e3"
         "9cf6c748837b61f6ee3adcee17534ed5",
     "790bc96880a99ba804bd12c0e6a22cc4"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "",
     "0100000000000000000000000000000002000000000000000000000000000000"
         "0300000000000000000000000000000004000000000000000000000000000000",
     "c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7"
         "e1049eb080883891a4db8caaa1f99dd004d80487540735234e3744512c6f90ce",
     "112864c269fc0d9d88c61fa47e39aa08"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "01",
     "0200000000000000",
     "1de22967237a8132",
     "91213f267e3b452f02d01ae33e4ec854"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "01",
     "020000000000000000000000",
     "163d6f9cc1b346cd453a2e4c",
     "c1a4a19ae800941ccdc57cc8413c277f"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "01",
     "02000000000000000000000000000000",
     "c91545823cc24f17dbb0e9e807d5ec17",
     "b292d28ff61189e8e49f3875ef91aff7"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "01",
     "0200000000000000000000000000000003000000000000000000000000000000",
     "07dad364bfc2b9da89116d7bef6daaaf6f255510aa654f920ac81b94e8bad365",
     "aea1bad12702e1965604374aab96dbbc"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "01",
     "0200000000000000000000000000000003000000000000000000000000000000"
         "04000000000000000000000000000000",
     "c67a1f0f567a5198aa1fcc8e3f21314336f7f51ca8b1af61feac35a86416fa47"
         "fbca3b5f749cdf564527f2314f42fe25",
     "03332742b228c647173616cfd44c54eb"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "01",
     "0200000000000000000000000000000003000000000000000000000000000000"
         "0400000000000000000000000000000005000000000000000000000000000000",
     "67fd45e126bfb9a79930c43aad2d36967d3f0e4d217c1e551f59727870beefc9"
         "8cb933a8fce9de887b1e40799988db1fc3f91880ed405b2dd298318858467c89",
     "5bde0285037c5de81e5b570a049b62a0"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "010000000000000000000000",
     "02000000",
     "22b3f4cd",
     "1835e517741dfddccfa07fa4661b74cf"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "010000000000000000000000000000000200",
     "0300000000000000000000000000000004000000",
     "43dd0163cdb48f9fe3212bf61b201976067f342b",
     "b879ad976d8242acc188ab59cabfe307"},
    {"0100000000000000000000000000000000000000000000000000000000000000",
     "030000000000000000000000",
     "0100000000000000000000000000000002000000",
     "030000000000000000000000000000000400",
     "462401724b5ce6588d5a54aae5375513a075",
     "cfcdf5042112aa29685c912fc2056543"},
    {"bae8e37fc83441b16034566b7a806c46bb91c3c5aedb64a6c590bc84d1a5e269",
     "e4b47801afc0577e34699b9e",
     "4fbdc66f14",
     "671fdd",
     "0eaccb",
     "93da9bb81333aee0c785b240d319719d"},
    {"6545fc880c94a95198874296d5cc1fd161320b6920ce07787f86743b275d1ab3",
     "2f6d1f0434d8848c1177441f",
     "6787f3ea22c127aaf195",
     "195495860f04",
     "a254dad4f3f9",
     "6b62b84dc40c84636a5ec12020ec8c2c"},
    {"d1894728b3fed1473c528b8426a582995929a1499e9ad8780c8d63d0ab4149c0",
     "9f572c614b4745914474e7c7",
     "489c8fde2be2cf97e74e932d4ed87d",
     "c9882e5386fd9f92ec",
     "0df9e308678244c44b",
     "c0fd3dc6628dfe55ebb0b9fb2295c8c2"},
    {"a44102952ef94b02b805249bac80e6f61455bfac8308a2d40d8c845117808235",
     "5c9e940fea2f582950a70d5a",
     "0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f",
     "1db2316fd568378da107b52b",
     "8dbeb9f7255bf5769dd56692",
     "404099c2587f64979f21826706d497d5"},
    {"9745b3d1ae06556fb6aa7890bebc18fe6b3db4da3d57aa94842b9803a96e07fb",
     "6de71860f762ebfbd08284e4",
     "f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f",
     "21702de0de18baa9c9596291b08466",
     "793576dfa5c0f88729a7ed3c2f1bff",
     "b3080d28f6ebb5d3648ce97bd5ba67fd"},
    {"b18853f68d833640e42a3c02c25b64869e146d7b233987bddfc240871d7576f7",
     "028ec6eb5ea7e298342a94d4",
     "9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac7",
     "b202b370ef9768ec6561c4fe6b7e7296fa85",
     "857e16a64915a787637687db4a9519635cdd",
     "454fc2a154fea91f8363a39fec7d0a49"},
    {"3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23",
     "688089e55540db1872504e1c",
     "734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f"
         "167541",
     "ced532ce4159b035277d4dfbb7db62968b13cd4eec",
     "626660c26ea6612fb17ad91e8e767639edd6c9faee",
     "9d6c7029675b89eaf4ba1ded1a286594"},
    {"0000000000000000000000000000000000000000000000000000000000000000",
     "000000000000000000000000",
     "",
     "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108",
     "f3f80f2cf0cb2dd9c5984fcda908456cc537703b5ba70324a6793a7bf218d3ea",
     "ffffffff000000000000000000000000"},
    {"0000000000000000000000000000000000000000000000000000000000000000",
     "000000000000000000000000",
     "",
     "eb3640277c7ffd1303c7a542d02d3e4c0000000000000000",
     "18ce4f0b8cb4d0cac65fea8f79257b20888e53e72299e56d",
     "ffffffff000000000000000000000000"},
};

std::vector<std::uint8_t> FromHex(const char* hex)
{
    auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };

    const std::size_t len = std::strlen(hex);
    std::vector<std::uint8_t> out;
    out.reserve(len / 2);
    for (std::size_t i = 0; i + 1 < len; i += 2) {
        out.push_back(static_cast<std::uint8_t>((digit(hex[i]) << 4) | digit(hex[i + 1])));
    }
    return out;
}

bb::AeadKey KeyFromHex(const char* hex)
{
    const std::vector<std::uint8_t> bytes = FromHex(hex);
    bb::AeadKey key{};
    if (bytes.size() == key.size()) {
        std::memcpy(key.data(), bytes.data(), key.size());
    }
    return key;
}

bb::AeadNonce NonceFromHex(const char* hex)
{
    const std::vector<std::uint8_t> bytes = FromHex(hex);
    bb::AeadNonce nonce{};
    if (bytes.size() == nonce.size()) {
        std::memcpy(nonce.data(), bytes.data(), nonce.size());
    }
    return nonce;
}

}  // namespace

// AES-256-GCM-SIV есть в default provider OpenSSL, но не в FIPS (§30). Если
// шифра нет, весь формат неработоспособен, и падать надо здесь, а не в первом
// же бэкапе.
BB_TEST(aead_cipher_is_available)
{
    BB_CHECK(bb::AeadIsAvailable());
}

BB_TEST(aead_rfc8452_vectors_seal)
{
    for (const Vector& v : kVectors) {
        const std::vector<std::uint8_t> aad   = FromHex(v.aad_hex);
        const std::vector<std::uint8_t> plain = FromHex(v.plaintext_hex);

        std::vector<std::uint8_t> sealed(bb::AeadSealedLen(plain.size()));
        std::size_t               produced = 0;

        BB_CHECK(bb::AeadSeal(KeyFromHex(v.key_hex), NonceFromHex(v.nonce_hex),
                              aad.data(), aad.size(),
                              plain.data(), plain.size(),
                              sealed.data(), sealed.size(), &produced));
        BB_CHECK_EQ(produced, sealed.size());

        const std::string expected =
            std::string(v.ciphertext_hex) + std::string(v.tag_hex);
        BB_CHECK_STR(bb::test::Hex(sealed.data(), sealed.size()).c_str(),
                     expected.c_str());
    }
}

BB_TEST(aead_rfc8452_vectors_open)
{
    for (const Vector& v : kVectors) {
        const std::vector<std::uint8_t> aad   = FromHex(v.aad_hex);
        const std::vector<std::uint8_t> plain = FromHex(v.plaintext_hex);

        const std::string sealed_hex =
            std::string(v.ciphertext_hex) + std::string(v.tag_hex);
        const std::vector<std::uint8_t> sealed = FromHex(sealed_hex.c_str());

        std::vector<std::uint8_t> opened(plain.size());
        std::size_t               produced = 0;

        BB_CHECK(bb::AeadOpen(KeyFromHex(v.key_hex), NonceFromHex(v.nonce_hex),
                              aad.data(), aad.size(),
                              sealed.data(), sealed.size(),
                              opened.data(), opened.size(), &produced));
        BB_CHECK_EQ(produced, plain.size());
        if (!plain.empty()) {
            BB_CHECK_EQ(std::memcmp(opened.data(), plain.data(), plain.size()), 0);
        }
    }
}
