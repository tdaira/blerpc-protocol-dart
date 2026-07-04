## 0.8.0

- Apache-2.0 relicense
- Version aligned with the blerpc protocol ecosystem (lockstep 0.8.0)

## 0.6.0

- Initial release
- Container serialize/deserialize, splitter, and assembler
- Control container factory functions (timeout, capabilities, stream end, error, key exchange)
- CommandPacket serialize/deserialize
- E2E encryption: X25519 ECDH, Ed25519 signatures, AES-128-GCM, HKDF-SHA256
- 4-step key exchange protocol with CentralKeyExchange and PeripheralKeyExchange
- BlerpcCryptoSession with counter management and replay detection
