// Known answer tests. Every expected value below comes from the published test
// vectors of the relevant specification, not from running this code and writing
// down what it printed.
#include <string>

#include "check.hpp"
#include "conduit/crypto.hpp"

using namespace conduit;
using namespace conduit::crypto;

CONDUIT_TEST(md5_matches_rfc1321_vectors) {
    CHECK_EQ(to_hex(byte_span(md5(as_bytes("")))),
             std::string("d41d8cd98f00b204e9800998ecf8427e"));
    CHECK_EQ(to_hex(byte_span(md5(as_bytes("abc")))),
             std::string("900150983cd24fb0d6963f7d28e17f72"));
    CHECK_EQ(to_hex(byte_span(md5(as_bytes(
                 "12345678901234567890123456789012345678901234567890123456789012345678901234567890")))),
             std::string("57edf4a22be3c955ac49da2e2107b67a"));
}

CONDUIT_TEST(sha1_matches_fips180_vectors) {
    CHECK_EQ(to_hex(byte_span(sha1(as_bytes("")))),
             std::string("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    CHECK_EQ(to_hex(byte_span(sha1(as_bytes("abc")))),
             std::string("a9993e364706816aba3e25717850c26c9cd0d89d"));
    CHECK_EQ(to_hex(byte_span(sha1(as_bytes(
                 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")))),
             std::string("84983e441c3bd26ebaae4aa1f95129e5e54670f1"));
}

CONDUIT_TEST(sha256_matches_fips180_vectors) {
    CHECK_EQ(to_hex(byte_span(sha256(as_bytes("")))),
             std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(to_hex(byte_span(sha256(as_bytes("abc")))),
             std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_EQ(to_hex(byte_span(sha256(as_bytes(
                 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")))),
             std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
}

CONDUIT_TEST(sha256_handles_a_message_that_needs_an_extra_block) {
    // 56 bytes: the padding byte plus the 8 byte length no longer fit, so the
    // implementation must emit a second block. This is where a naive padding
    // loop breaks.
    std::string msg(56, 'a');
    CHECK_EQ(to_hex(byte_span(sha256(as_bytes(msg)))),
             std::string("b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"));
}

CONDUIT_TEST(hmac_sha256_matches_rfc4231_case1) {
    std::vector<std::byte> key(20, std::byte{0x0b});
    auto mac = hmac_sha256(byte_span(key), as_bytes("Hi There"));
    CHECK_EQ(to_hex(byte_span(mac)),
             std::string("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
}

CONDUIT_TEST(hmac_sha256_hashes_an_oversized_key_first) {
    // RFC 4231 case 5 uses a 131 byte key, which exercises the branch where the
    // key is longer than the 64 byte block.
    std::vector<std::byte> key(131, std::byte{0xaa});
    auto mac = hmac_sha256(byte_span(key), as_bytes("Test Using Larger Than Block-Size Key - Hash Key First"));
    CHECK_EQ(to_hex(byte_span(mac)),
             std::string("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
}

CONDUIT_TEST(pbkdf2_sha256_matches_the_published_vector) {
    // RFC 7914 section 11 lists PBKDF2-HMAC-SHA-256 with password "passwd",
    // salt "salt", 1 iteration. The first 32 bytes of that output are one block.
    auto out = pbkdf2_sha256(as_bytes("passwd"), as_bytes("salt"), 1);
    CHECK_EQ(to_hex(byte_span(out)),
             std::string("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"));
}

CONDUIT_TEST(base64_round_trips_and_pads) {
    CHECK_EQ(base64_encode(as_bytes("")), std::string(""));
    CHECK_EQ(base64_encode(as_bytes("f")), std::string("Zg=="));
    CHECK_EQ(base64_encode(as_bytes("fo")), std::string("Zm8="));
    CHECK_EQ(base64_encode(as_bytes("foo")), std::string("Zm9v"));
    CHECK_EQ(base64_encode(as_bytes("foobar")), std::string("Zm9vYmFy"));

    auto back = base64_decode("Zm9vYmFy");
    CHECK_EQ(std::string(reinterpret_cast<const char*>(back.data()), back.size()),
             std::string("foobar"));
    CHECK_THROWS(base64_decode("!!!!"), protocol_error);
}

CONDUIT_TEST(pg_md5_password_follows_the_documented_formula) {
    // The formula is md5(md5(password + user) + salt), hex encoded at each step,
    // with the literal prefix "md5". Recomputed here from the parts so the test
    // checks the composition rather than a copied constant.
    auto salt = from_hex("01020304");
    auto got = pg_md5_password("secret", "alice", byte_span(salt));

    std::string inner = to_hex(byte_span(md5(as_bytes("secretalice"))));
    std::vector<std::byte> second(reinterpret_cast<const std::byte*>(inner.data()),
                                  reinterpret_cast<const std::byte*>(inner.data()) + inner.size());
    second.insert(second.end(), salt.begin(), salt.end());
    std::string want = "md5" + to_hex(byte_span(md5(byte_span(second))));

    CHECK_EQ(got, want);
    CHECK_EQ(got.size(), std::size_t{35});
    CHECK_EQ(got.substr(0, 3), std::string("md5"));
}

CONDUIT_TEST(mysql_native_password_is_xor_of_two_sha1_chains) {
    auto seed = from_hex("000102030405060708090a0b0c0d0e0f10111213");
    auto reply = mysql_native_password("hunter2", byte_span(seed));

    auto stage1 = sha1(as_bytes("hunter2"));
    auto stage2 = sha1(byte_span(stage1));
    std::vector<std::byte> seeded(seed.begin(), seed.end());
    seeded.insert(seeded.end(), stage2.begin(), stage2.end());
    auto scrambled = sha1(byte_span(seeded));

    for (std::size_t i = 0; i < reply.size(); ++i)
        CHECK_EQ(std::to_integer<int>(reply[i]),
                 std::to_integer<int>(scrambled[i] ^ stage1[i]));

    // Reapplying the scramble recovers SHA1(SHA1(password)), which is exactly
    // the check the server performs against the value it stores.
    std::vector<std::byte> recovered(reply.size());
    for (std::size_t i = 0; i < reply.size(); ++i) recovered[i] = reply[i] ^ scrambled[i];
    CHECK_EQ(to_hex(byte_span(recovered)), to_hex(byte_span(stage1)));
}
