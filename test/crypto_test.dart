import 'dart:typed_data';

import 'package:blerpc_protocol/blerpc_protocol.dart';
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  group('ControlCmd KEY_EXCHANGE', () {
    test('enum value', () {
      expect(ControlCmd.keyExchange.value, 0x6);
    });

    test('make key exchange container', () {
      final payload = Uint8List.fromList([0x01, ...List.filled(32, 0x00)]);
      final c = makeKeyExchange(5, payload);
      expect(c.controlCmd, ControlCmd.keyExchange);
      expect(c.payload, payload);
    });

    test('key exchange roundtrip', () {
      final payload = Uint8List.fromList([0x02, ...List.filled(128, 0xaa)]);
      final c = makeKeyExchange(10, payload);
      final data = c.serialize();
      final c2 = Container.deserialize(data);
      expect(c2.controlCmd, ControlCmd.keyExchange);
      expect(c2.payload, payload);
    });
  });

  group('Capabilities flags', () {
    test('encryption flag constant', () {
      expect(capabilityFlagEncryptionSupported, 0x0001);
    });

    test('capabilities request 6 bytes', () {
      final c = makeCapabilitiesRequest(
        1,
        maxRequestPayloadSize: 1024,
        maxResponsePayloadSize: 2048,
        flags: capabilityFlagEncryptionSupported,
      );
      expect(c.payload.length, 6);
      final bd = ByteData.sublistView(c.payload);
      expect(bd.getUint16(0, Endian.little), 1024);
      expect(bd.getUint16(2, Endian.little), 2048);
      expect(bd.getUint16(4, Endian.little), capabilityFlagEncryptionSupported);
    });

    test('capabilities response 6 bytes', () {
      final c = makeCapabilitiesResponse(
        2,
        maxRequestPayloadSize: 4096,
        maxResponsePayloadSize: 65535,
        flags: capabilityFlagEncryptionSupported,
      );
      expect(c.payload.length, 6);
      final bd = ByteData.sublistView(c.payload);
      expect(bd.getUint16(0, Endian.little), 4096);
      expect(bd.getUint16(2, Endian.little), 65535);
      expect(bd.getUint16(4, Endian.little), 1);
    });

    test('capabilities request default flags zero', () {
      final c = makeCapabilitiesRequest(3);
      final bd = ByteData.sublistView(c.payload);
      expect(bd.getUint16(4, Endian.little), 0);
    });

    test('capabilities response default flags zero', () {
      final c = makeCapabilitiesResponse(
        4,
        maxRequestPayloadSize: 100,
        maxResponsePayloadSize: 200,
      );
      final bd = ByteData.sublistView(c.payload);
      expect(bd.getUint16(4, Endian.little), 0);
    });
  });

  group('X25519', () {
    test('keygen produces 32-byte keys', () async {
      final (kp, pubkey) = await BlerpcCrypto.generateX25519KeyPair();
      final pubBytes = await BlerpcCrypto.x25519PublicBytes(kp);
      expect(pubkey.length, 32);
      expect(pubBytes.length, 32);
      expect(pubkey, pubBytes);
    });

    test('shared secret agreement', () async {
      final (privA, pubA) = await BlerpcCrypto.generateX25519KeyPair();
      final (privB, pubB) = await BlerpcCrypto.generateX25519KeyPair();

      final secretA = await BlerpcCrypto.x25519SharedSecret(privA, pubB);
      final secretB = await BlerpcCrypto.x25519SharedSecret(privB, pubA);

      expect(secretA.length, 32);
      expect(secretA, secretB);
    });

    test('different keys different secrets', () async {
      final (privA, _) = await BlerpcCrypto.generateX25519KeyPair();
      final (_, pubB) = await BlerpcCrypto.generateX25519KeyPair();
      final (_, pubC) = await BlerpcCrypto.generateX25519KeyPair();

      final secretAB = await BlerpcCrypto.x25519SharedSecret(privA, pubB);
      final secretAC = await BlerpcCrypto.x25519SharedSecret(privA, pubC);

      expect(secretAB, isNot(equals(secretAC)));
    });
  });

  group('Ed25519', () {
    test('sign verify roundtrip', () async {
      final (privkey, pubkey) = await BlerpcCrypto.generateEd25519KeyPair();
      final message = Uint8List.fromList('test message'.codeUnits);
      final signature = await BlerpcCrypto.ed25519Sign(privkey, message);

      expect(signature.length, 64);
      expect(
          await BlerpcCrypto.ed25519Verify(pubkey, message, signature), isTrue);
    });

    test('verify wrong message fails', () async {
      final (privkey, pubkey) = await BlerpcCrypto.generateEd25519KeyPair();
      final signature = await BlerpcCrypto.ed25519Sign(
          privkey, Uint8List.fromList('correct message'.codeUnits));
      expect(
          await BlerpcCrypto.ed25519Verify(
              pubkey, Uint8List.fromList('wrong message'.codeUnits), signature),
          isFalse);
    });

    test('verify wrong key fails', () async {
      final (priv1, pub1) = await BlerpcCrypto.generateEd25519KeyPair();
      final (_, pub2) = await BlerpcCrypto.generateEd25519KeyPair();

      final message = Uint8List.fromList('test'.codeUnits);
      final signature = await BlerpcCrypto.ed25519Sign(priv1, message);
      expect(
          await BlerpcCrypto.ed25519Verify(pub1, message, signature), isTrue);
      expect(
          await BlerpcCrypto.ed25519Verify(pub2, message, signature), isFalse);
    });

    test('load from bytes', () async {
      final (privkey, pubkey) = await BlerpcCrypto.generateEd25519KeyPair();
      final loaded = BlerpcCrypto.ed25519FromBytes(
          Uint8List.fromList(privkey.bytes), pubkey);
      final loadedPub = await BlerpcCrypto.ed25519PublicBytes(loaded);
      expect(loadedPub, pubkey);
    });
  });

  group('Session key derivation', () {
    test('derive produces 16 bytes', () async {
      final shared = Uint8List(32)..fillRange(0, 32, 0x42);
      final cPub = Uint8List(32)..fillRange(0, 32, 0xaa);
      final pPub = Uint8List(32)..fillRange(0, 32, 0xbb);
      final key = await BlerpcCrypto.deriveSessionKey(shared, cPub, pPub);
      expect(key.length, 16);
    });

    test('same inputs same key', () async {
      final shared = Uint8List(32)..fillRange(0, 32, 0x42);
      final cPub = Uint8List(32)..fillRange(0, 32, 0xaa);
      final pPub = Uint8List(32)..fillRange(0, 32, 0xbb);
      final key1 = await BlerpcCrypto.deriveSessionKey(shared, cPub, pPub);
      final key2 = await BlerpcCrypto.deriveSessionKey(shared, cPub, pPub);
      expect(key1, key2);
    });

    test('different pubkeys different key', () async {
      final shared = Uint8List(32)..fillRange(0, 32, 0x42);
      final cPubA = Uint8List(32)..fillRange(0, 32, 0xaa);
      final cPubB = Uint8List(32)..fillRange(0, 32, 0xcc);
      final pPub = Uint8List(32)..fillRange(0, 32, 0xbb);
      final key1 = await BlerpcCrypto.deriveSessionKey(shared, cPubA, pPub);
      final key2 = await BlerpcCrypto.deriveSessionKey(shared, cPubB, pPub);
      expect(key1, isNot(equals(key2)));
    });
  });

  group('AES-GCM encrypt/decrypt', () {
    test('encrypt decrypt command roundtrip', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final plaintext = Uint8List.fromList('Hello, blerpc!'.codeUnits);
      final encrypted =
          await BlerpcCrypto.encryptCommand(key, 0, directionC2P, plaintext);

      expect(encrypted.length, 4 + plaintext.length + 16);

      final (counter, decrypted) =
          await BlerpcCrypto.decryptCommand(key, directionC2P, encrypted);
      expect(counter, 0);
      expect(decrypted, plaintext);
    });

    test('different directions produce different ciphertext', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final plaintext = Uint8List.fromList('test'.codeUnits);
      final encC2P =
          await BlerpcCrypto.encryptCommand(key, 0, directionC2P, plaintext);
      final encP2C =
          await BlerpcCrypto.encryptCommand(key, 0, directionP2C, plaintext);
      expect(encC2P, isNot(equals(encP2C)));
    });

    test('wrong direction fails decrypt', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final encrypted = await BlerpcCrypto.encryptCommand(
          key, 0, directionC2P, Uint8List.fromList('test'.codeUnits));
      expect(
        () => BlerpcCrypto.decryptCommand(key, directionP2C, encrypted),
        throwsA(anything),
      );
    });

    test('wrong key fails decrypt', () async {
      final key1 = Uint8List(16)..fillRange(0, 16, 0x01);
      final key2 = Uint8List(16)..fillRange(0, 16, 0x02);
      final encrypted = await BlerpcCrypto.encryptCommand(
          key1, 0, directionC2P, Uint8List.fromList('test'.codeUnits));
      expect(
        () => BlerpcCrypto.decryptCommand(key2, directionC2P, encrypted),
        throwsA(anything),
      );
    });

    test('counter embedded in output', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final encrypted = await BlerpcCrypto.encryptCommand(
          key, 42, directionC2P, Uint8List.fromList('data'.codeUnits));
      final bd = ByteData.sublistView(encrypted);
      expect(bd.getUint32(0, Endian.little), 42);
    });

    test('empty plaintext', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final encrypted =
          await BlerpcCrypto.encryptCommand(key, 0, directionC2P, Uint8List(0));
      final (counter, decrypted) =
          await BlerpcCrypto.decryptCommand(key, directionC2P, encrypted);
      expect(counter, 0);
      expect(decrypted, isEmpty);
    });

    test('large plaintext', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final plaintext = Uint8List(10000)..fillRange(0, 10000, 0xff);
      final encrypted =
          await BlerpcCrypto.encryptCommand(key, 0, directionC2P, plaintext);
      final (_, decrypted) =
          await BlerpcCrypto.decryptCommand(key, directionC2P, encrypted);
      expect(decrypted, plaintext);
    });

    test('decrypt too short raises', () {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      expect(
        () => BlerpcCrypto.decryptCommand(key, directionC2P, Uint8List(19)),
        throwsA(isA<ArgumentError>()
            .having((e) => e.message, 'message', contains('too short'))),
      );
    });
  });

  group('Confirmation', () {
    test('encrypt decrypt confirmation roundtrip', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final encrypted =
          await BlerpcCrypto.encryptConfirmation(key, confirmCentral);
      expect(encrypted.length, 44);

      final plaintext = await BlerpcCrypto.decryptConfirmation(key, encrypted);
      expect(plaintext, confirmCentral);
    });

    test('different messages different output', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final encC = await BlerpcCrypto.encryptConfirmation(key, confirmCentral);
      final encP =
          await BlerpcCrypto.encryptConfirmation(key, confirmPeripheral);
      expect(encC, isNot(equals(encP)));
    });

    test('wrong key fails', () async {
      final key1 = Uint8List(16)..fillRange(0, 16, 0x01);
      final key2 = Uint8List(16)..fillRange(0, 16, 0x02);
      final encrypted =
          await BlerpcCrypto.encryptConfirmation(key1, confirmCentral);
      expect(
        () => BlerpcCrypto.decryptConfirmation(key2, encrypted),
        throwsA(anything),
      );
    });
  });

  group('Step payloads', () {
    test('step1 build parse', () {
      final pubkey = Uint8List(32)..fillRange(0, 32, 0xaa);
      final payload = BlerpcCrypto.buildStep1Payload(pubkey);
      expect(payload.length, 33);
      expect(payload[0], keyExchangeStep1);
      final parsed = BlerpcCrypto.parseStep1Payload(payload);
      expect(parsed, pubkey);
    });

    test('step2 build parse', () {
      final x25519Pub = Uint8List(32)..fillRange(0, 32, 0xaa);
      final signature = Uint8List(64)..fillRange(0, 64, 0xbb);
      final ed25519Pub = Uint8List(32)..fillRange(0, 32, 0xcc);
      final payload =
          BlerpcCrypto.buildStep2Payload(x25519Pub, signature, ed25519Pub);
      expect(payload.length, 129);
      expect(payload[0], keyExchangeStep2);
      final (pX25519, pSig, pEd25519) = BlerpcCrypto.parseStep2Payload(payload);
      expect(pX25519, x25519Pub);
      expect(pSig, signature);
      expect(pEd25519, ed25519Pub);
    });

    test('step3 build parse', () {
      final encrypted = Uint8List(44)..fillRange(0, 44, 0xdd);
      final payload = BlerpcCrypto.buildStep3Payload(encrypted);
      expect(payload.length, 45);
      expect(payload[0], keyExchangeStep3);
      final parsed = BlerpcCrypto.parseStep3Payload(payload);
      expect(parsed, encrypted);
    });

    test('step4 build parse', () {
      final encrypted = Uint8List(44)..fillRange(0, 44, 0xee);
      final payload = BlerpcCrypto.buildStep4Payload(encrypted);
      expect(payload.length, 45);
      expect(payload[0], keyExchangeStep4);
      final parsed = BlerpcCrypto.parseStep4Payload(payload);
      expect(parsed, encrypted);
    });

    test('step1 invalid short', () {
      expect(
        () => BlerpcCrypto.parseStep1Payload(
            Uint8List.fromList([0x01, ...List.filled(10, 0x00)])),
        throwsA(isA<ArgumentError>()
            .having((e) => e.message, 'message', contains('Invalid step 1'))),
      );
    });

    test('step1 invalid step byte', () {
      expect(
        () => BlerpcCrypto.parseStep1Payload(
            Uint8List.fromList([0x02, ...List.filled(32, 0x00)])),
        throwsA(isA<ArgumentError>()
            .having((e) => e.message, 'message', contains('Invalid step 1'))),
      );
    });

    test('step2 invalid short', () {
      expect(
        () => BlerpcCrypto.parseStep2Payload(
            Uint8List.fromList([0x02, ...List.filled(50, 0x00)])),
        throwsA(isA<ArgumentError>()
            .having((e) => e.message, 'message', contains('Invalid step 2'))),
      );
    });
  });

  group('Full key exchange flow', () {
    test('full handshake', () async {
      // Peripheral's long-term keys
      final (periphEdPriv, periphEdPub) =
          await BlerpcCrypto.generateEd25519KeyPair();
      final (periphXPriv, periphXPub) =
          await BlerpcCrypto.generateX25519KeyPair();

      // Step 1: Central generates ephemeral keypair
      final (centralXPriv, centralXPub) =
          await BlerpcCrypto.generateX25519KeyPair();
      final step1 = BlerpcCrypto.buildStep1Payload(centralXPub);
      final parsedCentralPub = BlerpcCrypto.parseStep1Payload(step1);
      expect(parsedCentralPub, centralXPub);

      // Step 2: Peripheral signs and responds
      final signMsg = Uint8List.fromList([...centralXPub, ...periphXPub]);
      final signature = await BlerpcCrypto.ed25519Sign(periphEdPriv, signMsg);
      final step2 =
          BlerpcCrypto.buildStep2Payload(periphXPub, signature, periphEdPub);

      // Central parses and verifies
      final (pXPub, pSig, pEdPub) = BlerpcCrypto.parseStep2Payload(step2);
      expect(pXPub, periphXPub);
      expect(await BlerpcCrypto.ed25519Verify(pEdPub, signMsg, pSig), isTrue);

      // Both derive shared secret and session key
      final sharedC =
          await BlerpcCrypto.x25519SharedSecret(centralXPriv, periphXPub);
      final sharedP =
          await BlerpcCrypto.x25519SharedSecret(periphXPriv, centralXPub);
      expect(sharedC, sharedP);

      final sessionKeyC =
          await BlerpcCrypto.deriveSessionKey(sharedC, centralXPub, periphXPub);
      final sessionKeyP =
          await BlerpcCrypto.deriveSessionKey(sharedP, centralXPub, periphXPub);
      expect(sessionKeyC, sessionKeyP);

      // Step 3: Central sends confirmation
      final encConfirmC =
          await BlerpcCrypto.encryptConfirmation(sessionKeyC, confirmCentral);
      final step3 = BlerpcCrypto.buildStep3Payload(encConfirmC);
      final parsedEnc = BlerpcCrypto.parseStep3Payload(step3);
      final decConfirmC =
          await BlerpcCrypto.decryptConfirmation(sessionKeyP, parsedEnc);
      expect(decConfirmC, confirmCentral);

      // Step 4: Peripheral sends confirmation
      final encConfirmP = await BlerpcCrypto.encryptConfirmation(
          sessionKeyP, confirmPeripheral);
      final step4 = BlerpcCrypto.buildStep4Payload(encConfirmP);
      final parsedEnc4 = BlerpcCrypto.parseStep4Payload(step4);
      final decConfirmP =
          await BlerpcCrypto.decryptConfirmation(sessionKeyC, parsedEnc4);
      expect(decConfirmP, confirmPeripheral);
    });

    test('encrypted command after handshake', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);

      // Central sends encrypted command (C->P)
      final plaintext = Uint8List.fromList('echo request data'.codeUnits);
      final encrypted =
          await BlerpcCrypto.encryptCommand(key, 0, directionC2P, plaintext);

      // Peripheral decrypts
      final (counter, decrypted) =
          await BlerpcCrypto.decryptCommand(key, directionC2P, encrypted);
      expect(counter, 0);
      expect(decrypted, plaintext);

      // Peripheral sends encrypted response (P->C)
      final respPlaintext = Uint8List.fromList('echo response data'.codeUnits);
      final respEncrypted = await BlerpcCrypto.encryptCommand(
          key, 0, directionP2C, respPlaintext);

      // Central decrypts
      final (respCounter, respDecrypted) =
          await BlerpcCrypto.decryptCommand(key, directionP2C, respEncrypted);
      expect(respCounter, 0);
      expect(respDecrypted, respPlaintext);
    });

    test('counter monotonic increase', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);

      for (var i = 0; i < 5; i++) {
        final encrypted = await BlerpcCrypto.encryptCommand(
            key, i, directionC2P, Uint8List.fromList('msg$i'.codeUnits));
        final (counter, decrypted) =
            await BlerpcCrypto.decryptCommand(key, directionC2P, encrypted);
        expect(counter, i);
        expect(decrypted, Uint8List.fromList('msg$i'.codeUnits));
      }
    });
  });

  group('BlerpcCryptoSession', () {
    test('encrypt decrypt roundtrip', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final central = BlerpcCryptoSession(key, isCentral: true);
      final peripheral = BlerpcCryptoSession(key, isCentral: false);

      final plaintext = Uint8List.fromList('Hello, blerpc!'.codeUnits);
      final encrypted = await central.encrypt(plaintext);
      final decrypted = await peripheral.decrypt(encrypted);
      expect(decrypted, plaintext);
    });

    test('bidirectional', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final central = BlerpcCryptoSession(key, isCentral: true);
      final peripheral = BlerpcCryptoSession(key, isCentral: false);

      // Central -> Peripheral
      final enc1 =
          await central.encrypt(Uint8List.fromList('request'.codeUnits));
      expect(await peripheral.decrypt(enc1),
          Uint8List.fromList('request'.codeUnits));

      // Peripheral -> Central
      final enc2 =
          await peripheral.encrypt(Uint8List.fromList('response'.codeUnits));
      expect(await central.decrypt(enc2),
          Uint8List.fromList('response'.codeUnits));
    });

    test('counter auto increment', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final central = BlerpcCryptoSession(key, isCentral: true);
      final peripheral = BlerpcCryptoSession(key, isCentral: false);

      for (var i = 0; i < 5; i++) {
        final enc =
            await central.encrypt(Uint8List.fromList('msg$i'.codeUnits));
        final bd = ByteData.sublistView(enc);
        expect(bd.getUint32(0, Endian.little), i);
        expect(await peripheral.decrypt(enc),
            Uint8List.fromList('msg$i'.codeUnits));
      }
    });

    test('replay detection', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final central = BlerpcCryptoSession(key, isCentral: true);
      final peripheral = BlerpcCryptoSession(key, isCentral: false);

      final enc0 = await central.encrypt(Uint8List.fromList('msg0'.codeUnits));
      final enc1 = await central.encrypt(Uint8List.fromList('msg1'.codeUnits));

      await peripheral.decrypt(enc0);
      await peripheral.decrypt(enc1);

      // Replaying enc0 should fail
      expect(
        () => peripheral.decrypt(enc0),
        throwsA(isA<StateError>()
            .having((e) => e.message, 'message', contains('Replay'))),
      );
    });

    test('counter zero replay attack', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final central = BlerpcCryptoSession(key, isCentral: true);
      final peripheral = BlerpcCryptoSession(key, isCentral: false);

      final enc0 = await central.encrypt(Uint8List.fromList('msg0'.codeUnits));
      await peripheral.decrypt(enc0);

      // Replaying counter-0 message should fail
      expect(
        () => peripheral.decrypt(enc0),
        throwsA(isA<StateError>()
            .having((e) => e.message, 'message', contains('Replay'))),
      );
    });

    test('wrong direction fails', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final central = BlerpcCryptoSession(key, isCentral: true);

      final enc = await central.encrypt(Uint8List.fromList('test'.codeUnits));
      expect(
        () => central.decrypt(enc),
        throwsA(anything),
      );
    });
  });

  group('CentralKeyExchange', () {
    Future<(SimpleKeyPair, Uint8List, SimpleKeyPairData, Uint8List)>
        makePeripheralKeys() async {
      final (xPriv, xPub) = await BlerpcCrypto.generateX25519KeyPair();
      final (edPriv, edPub) = await BlerpcCrypto.generateEd25519KeyPair();
      return (xPriv, xPub, edPriv, edPub);
    }

    test('start produces step1', () async {
      final kx = CentralKeyExchange();
      final step1 = await kx.start();
      expect(step1.length, 33);
      expect(step1[0], keyExchangeStep1);
    });

    test('processStep2 verifies signature', () async {
      final kx = CentralKeyExchange();
      final step1 = await kx.start();
      final centralPub = BlerpcCrypto.parseStep1Payload(step1);

      final (_, xPub, edPriv, edPub) = await makePeripheralKeys();

      final signMsg = Uint8List.fromList([...centralPub, ...xPub]);
      final signature = await BlerpcCrypto.ed25519Sign(edPriv, signMsg);
      final step2 = BlerpcCrypto.buildStep2Payload(xPub, signature, edPub);

      final step3 = await kx.processStep2(step2);
      expect(step3.length, 45);
      expect(step3[0], keyExchangeStep3);
    });

    test('processStep2 bad signature raises', () async {
      final kx = CentralKeyExchange();
      await kx.start();

      final (_, xPub, _, edPub) = await makePeripheralKeys();
      final badSig = Uint8List(64);
      final step2 = BlerpcCrypto.buildStep2Payload(xPub, badSig, edPub);

      expect(
        () => kx.processStep2(step2),
        throwsA(isA<ArgumentError>()
            .having((e) => e.message, 'message', contains('signature'))),
      );
    });

    test('verify key callback reject', () async {
      final kx = CentralKeyExchange();
      final step1 = await kx.start();
      final centralPub = BlerpcCrypto.parseStep1Payload(step1);

      final (_, xPub, edPriv, edPub) = await makePeripheralKeys();
      final signMsg = Uint8List.fromList([...centralPub, ...xPub]);
      final signature = await BlerpcCrypto.ed25519Sign(edPriv, signMsg);
      final step2 = BlerpcCrypto.buildStep2Payload(xPub, signature, edPub);

      expect(
        () => kx.processStep2(step2, verifyKeyCb: (_) => false),
        throwsA(isA<ArgumentError>()
            .having((e) => e.message, 'message', contains('rejected'))),
      );
    });

    test('verify key callback accept', () async {
      final kx = CentralKeyExchange();
      final step1 = await kx.start();
      final centralPub = BlerpcCrypto.parseStep1Payload(step1);

      final (_, xPub, edPriv, edPub) = await makePeripheralKeys();
      final signMsg = Uint8List.fromList([...centralPub, ...xPub]);
      final signature = await BlerpcCrypto.ed25519Sign(edPriv, signMsg);
      final step2 = BlerpcCrypto.buildStep2Payload(xPub, signature, edPub);

      Uint8List? receivedKey;
      final step3 = await kx.processStep2(step2, verifyKeyCb: (k) {
        receivedKey = k;
        return true;
      });
      expect(receivedKey, edPub);
      expect(step3.length, 45);
    });
  });

  group('PeripheralKeyExchange', () {
    test('processStep1 produces step2', () async {
      final (edPriv, _) = await BlerpcCrypto.generateEd25519KeyPair();
      final kx = PeripheralKeyExchange(edPriv);
      final (_, centralXPub) = await BlerpcCrypto.generateX25519KeyPair();
      final step1 = BlerpcCrypto.buildStep1Payload(centralXPub);

      final step2 = await kx.processStep1(step1);
      expect(step2.length, 129);
      expect(step2[0], keyExchangeStep2);
    });

    test('processStep3 bad confirmation raises', () async {
      final (edPriv, _) = await BlerpcCrypto.generateEd25519KeyPair();
      final kx = PeripheralKeyExchange(edPriv);
      final (_, centralXPub) = await BlerpcCrypto.generateX25519KeyPair();
      final step1 = BlerpcCrypto.buildStep1Payload(centralXPub);
      await kx.processStep1(step1);

      // Build a step 3 with wrong confirmation text
      final badEncrypted = await BlerpcCrypto.encryptConfirmation(
          kx.sessionKey!, Uint8List.fromList('WRONG_CONFIRM_XX'.codeUnits));
      final badStep3 = BlerpcCrypto.buildStep3Payload(badEncrypted);

      expect(
        () => kx.processStep3(badStep3),
        throwsA(isA<ArgumentError>()
            .having((e) => e.message, 'message', contains('confirmation'))),
      );
    });
  });

  group('Key exchange integration', () {
    test('full handshake and session', () async {
      final (periphEdPriv, _) = await BlerpcCrypto.generateEd25519KeyPair();

      final centralKx = CentralKeyExchange();
      final periphKx = PeripheralKeyExchange(periphEdPriv);

      final step1 = await centralKx.start();
      final step2 = await periphKx.processStep1(step1);
      final step3 = await centralKx.processStep2(step2);
      final (step4, periphSession) = await periphKx.processStep3(step3);
      final centralSession = await centralKx.finish(step4);

      // Bidirectional encrypted communication
      final encReq = await centralSession
          .encrypt(Uint8List.fromList('echo request'.codeUnits));
      expect(await periphSession.decrypt(encReq),
          Uint8List.fromList('echo request'.codeUnits));

      final encResp = await periphSession
          .encrypt(Uint8List.fromList('echo response'.codeUnits));
      expect(await centralSession.decrypt(encResp),
          Uint8List.fromList('echo response'.codeUnits));
    });

    test('handshake with verify callback', () async {
      final (periphEdPriv, periphEdPub) =
          await BlerpcCrypto.generateEd25519KeyPair();

      final centralKx = CentralKeyExchange();
      final periphKx = PeripheralKeyExchange(periphEdPriv);

      final step1 = await centralKx.start();
      final step2 = await periphKx.processStep1(step1);

      final seenKeys = <Uint8List>[];
      final step3 = await centralKx.processStep2(step2, verifyKeyCb: (k) {
        seenKeys.add(k);
        return true;
      });
      expect(seenKeys[0], periphEdPub);

      final (step4, periphSession) = await periphKx.processStep3(step3);
      final centralSession = await centralKx.finish(step4);

      final enc =
          await centralSession.encrypt(Uint8List.fromList('test'.codeUnits));
      expect(await periphSession.decrypt(enc),
          Uint8List.fromList('test'.codeUnits));
    });

    test('multiple messages after handshake', () async {
      final (periphEdPriv, _) = await BlerpcCrypto.generateEd25519KeyPair();

      final centralKx = CentralKeyExchange();
      final periphKx = PeripheralKeyExchange(periphEdPriv);

      final step1 = await centralKx.start();
      final step2 = await periphKx.processStep1(step1);
      final step3 = await centralKx.processStep2(step2);
      final (step4, periphSession) = await periphKx.processStep3(step3);
      final centralSession = await centralKx.finish(step4);

      for (var i = 0; i < 20; i++) {
        final msg = Uint8List.fromList('c2p_$i'.codeUnits);
        final enc = await centralSession.encrypt(msg);
        expect(await periphSession.decrypt(enc), msg);

        final resp = Uint8List.fromList('p2c_$i'.codeUnits);
        final encResp = await periphSession.encrypt(resp);
        expect(await centralSession.decrypt(encResp), resp);
      }
    });
  });

  group('Peripheral handleStep', () {
    test('handle step 1', () async {
      final (edPriv, _) = await BlerpcCrypto.generateEd25519KeyPair();
      final kx = PeripheralKeyExchange(edPriv);
      final (_, centralXPub) = await BlerpcCrypto.generateX25519KeyPair();
      final step1 = BlerpcCrypto.buildStep1Payload(centralXPub);

      final (response, session) = await kx.handleStep(step1);
      expect(response[0], keyExchangeStep2);
      expect(response.length, 129);
      expect(session, isNull);
    });

    test('handle step 3', () async {
      final (edPriv, _) = await BlerpcCrypto.generateEd25519KeyPair();
      final kx = PeripheralKeyExchange(edPriv);
      final centralKx = CentralKeyExchange();

      final step1 = await centralKx.start();
      final (step2, session1) = await kx.handleStep(step1);
      expect(session1, isNull);

      final step3 = await centralKx.processStep2(step2);
      final (step4, session2) = await kx.handleStep(step3);
      expect(step4[0], keyExchangeStep4);
      expect(step4.length, 45);
      expect(session2, isNotNull);
    });

    test('handle step invalid', () async {
      final (edPriv, _) = await BlerpcCrypto.generateEd25519KeyPair();
      final kx = PeripheralKeyExchange(edPriv);
      expect(
        () => kx
            .handleStep(Uint8List.fromList([0x02, ...List.filled(128, 0x00)])),
        throwsA(isA<ArgumentError>()
            .having((e) => e.message, 'message', contains('Invalid'))),
      );
    });

    test('handle step empty payload', () async {
      final (edPriv, _) = await BlerpcCrypto.generateEd25519KeyPair();
      final kx = PeripheralKeyExchange(edPriv);
      expect(
        () => kx.handleStep(Uint8List(0)),
        throwsA(isA<ArgumentError>()
            .having((e) => e.message, 'message', contains('Empty'))),
      );
    });
  });

  group('centralPerformKeyExchange', () {
    test('full handshake', () async {
      final (periphEdPriv, _) = await BlerpcCrypto.generateEd25519KeyPair();
      final periphKx = PeripheralKeyExchange(periphEdPriv);

      final payloads = <Uint8List>[];

      Future<void> mockSend(Uint8List payload) async {
        final (response, _) = await periphKx.handleStep(payload);
        payloads.add(response);
      }

      Future<Uint8List> mockReceive() async {
        return payloads.removeAt(0);
      }

      final session = await centralPerformKeyExchange(
        send: mockSend,
        receive: mockReceive,
      );

      // Verify session works
      final periphSession =
          BlerpcCryptoSession(periphKx.sessionKey!, isCentral: false);
      final enc = await session.encrypt(Uint8List.fromList('test'.codeUnits));
      expect(await periphSession.decrypt(enc),
          Uint8List.fromList('test'.codeUnits));
    });

    test('verify callback reject', () async {
      final (periphEdPriv, _) = await BlerpcCrypto.generateEd25519KeyPair();
      final periphKx = PeripheralKeyExchange(periphEdPriv);

      final payloads = <Uint8List>[];

      Future<void> mockSend(Uint8List payload) async {
        final (response, _) = await periphKx.handleStep(payload);
        payloads.add(response);
      }

      Future<Uint8List> mockReceive() async {
        return payloads.removeAt(0);
      }

      expect(
        () => centralPerformKeyExchange(
          send: mockSend,
          receive: mockReceive,
          verifyKeyCb: (_) => false,
        ),
        throwsA(isA<ArgumentError>()
            .having((e) => e.message, 'message', contains('rejected'))),
      );
    });

    test('verify callback accept', () async {
      final (periphEdPriv, periphEdPub) =
          await BlerpcCrypto.generateEd25519KeyPair();
      final periphKx = PeripheralKeyExchange(periphEdPriv);

      final payloads = <Uint8List>[];
      final seenKeys = <Uint8List>[];

      Future<void> mockSend(Uint8List payload) async {
        final (response, _) = await periphKx.handleStep(payload);
        payloads.add(response);
      }

      Future<Uint8List> mockReceive() async {
        return payloads.removeAt(0);
      }

      final session = await centralPerformKeyExchange(
        send: mockSend,
        receive: mockReceive,
        verifyKeyCb: (k) {
          seenKeys.add(k);
          return true;
        },
      );
      expect(session, isNotNull);
      expect(seenKeys[0], periphEdPub);
    });
  });

  group('Key exchange state validation', () {
    test('central processStep2 before start raises', () {
      final kx = CentralKeyExchange();
      expect(
        () => kx.processStep2(
            Uint8List.fromList([0x02, ...List.filled(128, 0x00)])),
        throwsA(isA<StateError>()),
      );
    });

    test('central finish before processStep2 raises', () async {
      final kx = CentralKeyExchange();
      await kx.start();
      expect(
        () => kx.finish(Uint8List.fromList([0x04, ...List.filled(44, 0x00)])),
        throwsA(isA<StateError>()),
      );
    });

    test('central double start raises', () async {
      final kx = CentralKeyExchange();
      await kx.start();
      expect(
        () => kx.start(),
        throwsA(isA<StateError>()),
      );
    });

    test('peripheral processStep3 before step1 raises', () async {
      final (edPriv, _) = await BlerpcCrypto.generateEd25519KeyPair();
      final kx = PeripheralKeyExchange(edPriv);
      expect(
        () => kx
            .processStep3(Uint8List.fromList([0x03, ...List.filled(44, 0x00)])),
        throwsA(isA<StateError>()),
      );
    });

    test('peripheral handleStep3 before step1 raises', () async {
      final (edPriv, _) = await BlerpcCrypto.generateEd25519KeyPair();
      final kx = PeripheralKeyExchange(edPriv);
      expect(
        () =>
            kx.handleStep(Uint8List.fromList([0x03, ...List.filled(44, 0x00)])),
        throwsA(isA<StateError>()),
      );
    });

    test('peripheral double step1 raises', () async {
      final (edPriv, _) = await BlerpcCrypto.generateEd25519KeyPair();
      final kx = PeripheralKeyExchange(edPriv);
      final centralKx = CentralKeyExchange();
      final step1 = await centralKx.start();
      await kx.processStep1(step1);
      expect(
        () => kx.processStep1(step1),
        throwsA(isA<StateError>()),
      );
    });

    test('peripheral reset allows new handshake', () async {
      final (edPriv, _) = await BlerpcCrypto.generateEd25519KeyPair();
      final kx = PeripheralKeyExchange(edPriv);

      final centralKx = CentralKeyExchange();
      final step1 = await centralKx.start();
      await kx.processStep1(step1);

      kx.reset();

      final centralKx2 = CentralKeyExchange();
      final step1b = await centralKx2.start();
      final step2 = await kx.processStep1(step1b);
      expect(step2.length, 129);
    });
  });

  group('CryptoSession counter overflow', () {
    test('encrypt at max counter raises', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final session = BlerpcCryptoSession(key, isCentral: true);
      session.txCounter = 0xFFFFFFFF;
      expect(
        () => session.encrypt(Uint8List.fromList('test'.codeUnits)),
        throwsA(isA<StateError>()
            .having((e) => e.message, 'message', contains('overflow'))),
      );
    });

    test('encrypt below max counter works', () async {
      final key = Uint8List(16)..fillRange(0, 16, 0x01);
      final session = BlerpcCryptoSession(key, isCentral: true);
      session.txCounter = 0xFFFFFFFE;
      final encrypted =
          await session.encrypt(Uint8List.fromList('test'.codeUnits));
      expect(encrypted.length, greaterThan(0));
    });
  });
}
