|Protected area|Threat|Intended mitigation|
|-|-|-|
|Master password|An attacker guesses / brute-forces the master password after stealing the user credentials.|Use a strong master password (advise user to create a strong one) and a slow password-based key-derivation function (Argon2id or PBKDF2) with a unique salt. Never store the master password!|
|Master password|The password is exposed (logs, screen display, error messages, etc.)|Hide password input, never log passwords, clear temporary password data from memory when possible. The password should no permanently be stored as plain text.|
|Master password|Unlimited login attempts make guessing correct password easier and more likely.|Set a limit for entering the password in a defined period of time. Use login delay / rate limiting. |
|Vault at rest|An attacker copies / steals the vault file.|Encrypt the vault using authenticated encryption (AES-256-GCM / ChaCha20-Poly1305)|
|Vault at rest|An attacker modifies the encrypted vault.|Verify the authentication tag before decryption. If verification fails, reject the vault + show an error that was triggered.|
|Vault at rest|A nonce is reused or generated predictably.|Generate a fresh and unpredictable nonce for every encryption operation by using a secure random-number generator.|
|Vault at rest|Plaintext passwords appear in temporary files, backups, or logs.|Never write plaintext credentials!|
|Vault in memory|Malware or another process reads decrypted passwords / the encryption key from memory.|Keep sensitive data in memory only while needed and lock the session automatically, after that clear sensitive buffers after use.|
|Vault in memory|Secrets remain in memory after the user locks the vault.|Securely clear the derived key and decrypted vault data.|
|User interface|Someone sees the user entering / viewing a password.|Mask password fields, reveal stored passwords only when requested.|
|User interface|A user accesses the vault without authentication.|Keep the vault locked by default and require successful authentication before usage.|
|User interface|Weak passwords are generated.|Use a cryptographically secure random-number generator and generate passwords with sufficient length + complexity.|



