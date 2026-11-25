#include "vault_crypto.h"
#include "vault_records.h"
#include <iostream>

int failures = 0;
void check(bool ok, const char* label)
{
    if (!ok)
    {
        ++failures;
        std::cerr << "Failed: " << label << '\n';
    }
}

bool roundTrip(const VaultKey& key, const std::string& binding, const std::string& plain,
    const VaultKey& openKey, const std::string& openBinding, std::string& opened)
{
    std::string nonceHex, encryptedHex;
    if (!sealVaultData(plain, key, binding, nonceHex, encryptedHex)) return false;
    const std::string salt(crypto_pwhash_SALTBYTES * 2, '0');
    VaultFile header;
    VaultBytes bytes;
    return parseVaultFile(formatVaultFile(salt, nonceHex.c_str(), encryptedHex.c_str(), 3), header) &&
        decodeVaultFile(header, bytes) && openVaultData(bytes, openKey, openBinding, opened);
}

int main()
{
    if (sodium_init() < 0) return 1;
    const unsigned char salt[crypto_pwhash_SALTBYTES] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    VaultKey key{};
    VaultKey again{};
    VaultKey older{};
    std::string password = "purple tiger eats noodles";
    check(deriveVaultKey(password, salt, 3, key), "derive a version 3 key");
    check(password.empty(), "key derivation wipes the master password");
    password = "purple tiger eats noodles";
    check(deriveVaultKey(password, salt, 3, again) && sodium_memcmp(key, again, sizeof key) == 0,
        "same password and salt give the same key");
    password = "purple tiger eats noodles";
    check(deriveVaultKey(password, salt, 2, older) && sodium_memcmp(key, older, sizeof key) != 0,
        "version 2 keeps its own key derivation cost");
    VaultKey wrong{};
    password = "purple tiger eats noodlez";
    check(deriveVaultKey(password, salt, 3, wrong) && sodium_memcmp(key, wrong, sizeof key) != 0,
        "a one-character change gives a different key");

    std::deque<Entry> entries;
    Entry& entry = entries.emplace_back();
    entry.service = "bank";
    entry.username = "nastya";
    entry.password = "s3cret \"quoted\" \\ value";
    std::string plain;
    StringWiper wipePlain(plain);
    serializeEntries(entries, plain);

    const std::string owner = "password-manager/v2/uid-1000";
    std::string opened;
    StringWiper wipeOpened(opened);
    check(roundTrip(key, owner, plain, key, owner, opened) && opened == plain, "encrypt then decrypt returns the records");
    std::deque<Entry> loaded;
    check(parseEntries(opened, loaded) && loaded.size() == 1 && loaded.front().password == entry.password,
        "decrypted records parse back to the same entry");
    check(!roundTrip(key, owner, plain, wrong, owner, opened) && opened.empty(), "wrong key is rejected and leaves no output");
    check(!roundTrip(key, owner, plain, key, "password-manager/v2/uid-1001", opened), "another account is rejected");
    check(roundTrip(key, owner, "[]", key, owner, opened) && opened == "[]", "empty vault round trip");

    std::string nonceA, nonceB, encryptedA, encryptedB;
    check(sealVaultData(plain, key, owner, nonceA, encryptedA) && sealVaultData(plain, key, owner, nonceB, encryptedB) &&
        nonceA != nonceB && encryptedA != encryptedB, "every save uses a fresh nonce");
    check(encryptedA.find("s3cret") == std::string::npos && encryptedA.find("bank") == std::string::npos,
        "ciphertext does not contain the plaintext");

    VaultFile header;
    const std::string saltHex(crypto_pwhash_SALTBYTES * 2, '0');
    check(parseVaultFile(formatVaultFile(saltHex, nonceA.c_str(), encryptedA.c_str(), 3), header), "parse sealed file");
    VaultBytes bytes;
    check(decodeVaultFile(header, bytes) && openVaultData(bytes, key, owner, opened), "untouched file opens");
    for (std::size_t i : {std::size_t{0}, bytes.encrypted.size() / 2, bytes.encrypted.size() - 1})
    {
        VaultBytes changed = bytes;
        changed.encrypted[i] ^= 1;
        check(!openVaultData(changed, key, owner, opened) && opened.empty(), "changed ciphertext or tag is rejected");
    }
    VaultBytes changedNonce = bytes;
    changedNonce.nonce[0] ^= 1;
    check(!openVaultData(changedNonce, key, owner, opened), "changed nonce is rejected");
    VaultBytes cut = bytes;
    cut.encrypted.resize(cut.encrypted.size() - 1);
    check(!openVaultData(cut, key, owner, opened), "truncated data is rejected");

    sodium_memzero(key, sizeof key);
    sodium_memzero(again, sizeof again);
    sodium_memzero(older, sizeof older);
    sodium_memzero(wrong, sizeof wrong);
    if (failures == 0) std::cout << "Encryption and decryption tests passed\n";
    return failures == 0 ? 0 : 1;
}
