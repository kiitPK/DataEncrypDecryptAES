This app encrypts a given data block using AES. The encryption key is derived in a secure way
(random salt, 1000 rounds of SHA-256). The encryption uses AES in CBC mode with random IV.
Note that the data stored in the class EncryptedData (salt, iv, and encryptedData) can be concatenated to a single
byte array. You can then save the data or transmit it to the recipient.
