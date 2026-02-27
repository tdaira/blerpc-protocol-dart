// E2E encryption for blerpc using X25519, Ed25519, AES-128-GCM, HKDF-SHA256.
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

// Direction bytes for nonce construction
const int directionC2P = 0x00;
const int directionP2C = 0x01;

// Confirmation plaintexts
final Uint8List confirmCentral =
    Uint8List.fromList('BLERPC_CONFIRM_C'.codeUnits);
final Uint8List confirmPeripheral =
    Uint8List.fromList('BLERPC_CONFIRM_P'.codeUnits);

// Key exchange step constants
const int keyExchangeStep1 = 0x01;
const int keyExchangeStep2 = 0x02;
const int keyExchangeStep3 = 0x03;
const int keyExchangeStep4 = 0x04;

/// Cryptographic operations for blerpc E2E encryption.
class BlerpcCrypto {
  static final _x25519 = X25519();
  static final _ed25519 = Ed25519();
  static final _aesGcm = AesGcm.with128bits(nonceLength: 12);
  static final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 16);

  /// Generate an X25519 key pair.
  /// Returns (SimpleKeyPair, publicKeyBytes32).
  static Future<(SimpleKeyPair, Uint8List)> generateX25519KeyPair() async {
    final kp = await _x25519.newKeyPair();
    final pub = await kp.extractPublicKey();
    return (kp, Uint8List.fromList(pub.bytes));
  }

  /// Get the raw 32-byte public key from a key pair.
  static Future<Uint8List> x25519PublicBytes(SimpleKeyPair keyPair) async {
    final pub = await keyPair.extractPublicKey();
    return Uint8List.fromList(pub.bytes);
  }

  /// Compute X25519 shared secret (32 bytes).
  static Future<Uint8List> x25519SharedSecret(
      SimpleKeyPair privateKey, Uint8List peerPublicBytes) async {
    final peerPub = SimplePublicKey(peerPublicBytes, type: KeyPairType.x25519);
    final secret = await _x25519.sharedSecretKey(
      keyPair: privateKey,
      remotePublicKey: peerPub,
    );
    final bytes = await secret.extractBytes();
    return Uint8List.fromList(bytes);
  }

  /// Derive 16-byte AES-128 session key using HKDF-SHA256.
  ///
  /// salt = centralPubkey || peripheralPubkey (64 bytes)
  /// info = "blerpc-session-key"
  static Future<Uint8List> deriveSessionKey(
    Uint8List sharedSecret,
    Uint8List centralPubkey,
    Uint8List peripheralPubkey,
  ) async {
    final salt = Uint8List.fromList([...centralPubkey, ...peripheralPubkey]);
    final secretKey = SecretKey(sharedSecret);
    final derived = await _hkdf.deriveKey(
      secretKey: secretKey,
      nonce: salt,
      info: 'blerpc-session-key'.codeUnits,
    );
    final bytes = await derived.extractBytes();
    return Uint8List.fromList(bytes);
  }

  /// Generate an Ed25519 key pair.
  /// Returns (SimpleKeyPairData, publicKeyBytes32).
  static Future<(SimpleKeyPairData, Uint8List)> generateEd25519KeyPair() async {
    final kp = await _ed25519.newKeyPair();
    final pub = await kp.extractPublicKey();
    final kpData = await kp.extract();
    return (kpData, Uint8List.fromList(pub.bytes));
  }

  /// Get the raw 32-byte public key from an Ed25519 key pair.
  static Future<Uint8List> ed25519PublicBytes(SimpleKeyPairData keyPair) async {
    final pub = keyPair.publicKey;
    return Uint8List.fromList(pub.bytes);
  }

  /// Sign a message with Ed25519. Returns 64-byte signature.
  static Future<Uint8List> ed25519Sign(
      SimpleKeyPairData privateKey, Uint8List message) async {
    final sig = await _ed25519.sign(message,
        keyPair: SimpleKeyPairData(
          privateKey.bytes,
          publicKey: privateKey.publicKey,
          type: KeyPairType.ed25519,
        ));
    return Uint8List.fromList(sig.bytes);
  }

  /// Verify an Ed25519 signature. Returns true if valid.
  static Future<bool> ed25519Verify(
      Uint8List publicKeyBytes, Uint8List message, Uint8List signature) async {
    try {
      final pub = SimplePublicKey(publicKeyBytes, type: KeyPairType.ed25519);
      final sig = Signature(signature, publicKey: pub);
      final valid = await _ed25519.verify(message, signature: sig);
      return valid;
    } catch (_) {
      return false;
    }
  }

  /// Load Ed25519 key pair from raw 32-byte seed + public key.
  static SimpleKeyPairData ed25519FromBytes(
      Uint8List seed, Uint8List publicKey) {
    return SimpleKeyPairData(
      seed,
      publicKey: SimplePublicKey(publicKey, type: KeyPairType.ed25519),
      type: KeyPairType.ed25519,
    );
  }

  /// Build 12-byte AES-GCM nonce: counter(4B LE) || direction(1B) || zeros(7B).
  static Uint8List _buildNonce(int counter, int direction) {
    final buf = ByteData(12);
    buf.setUint32(0, counter, Endian.little);
    buf.setUint8(4, direction);
    // bytes 5-11 are already zero
    return buf.buffer.asUint8List();
  }

  /// Encrypt a command payload.
  ///
  /// Returns: [counter:4BLE][ciphertext:NB][tag:16B]
  static Future<Uint8List> encryptCommand(Uint8List sessionKey, int counter,
      int direction, Uint8List plaintext) async {
    final nonce = _buildNonce(counter, direction);
    final key = SecretKey(sessionKey);
    final secretBox = await _aesGcm.encrypt(
      plaintext,
      secretKey: key,
      nonce: nonce,
    );
    // counter(4) + ciphertext + mac(16)
    final counterBytes = ByteData(4)..setUint32(0, counter, Endian.little);
    return Uint8List.fromList([
      ...counterBytes.buffer.asUint8List(),
      ...secretBox.cipherText,
      ...secretBox.mac.bytes,
    ]);
  }

  /// Decrypt a command payload.
  ///
  /// Input: [counter:4BLE][ciphertext:NB][tag:16B]
  /// Returns: (counter, plaintext)
  static Future<(int, Uint8List)> decryptCommand(
      Uint8List sessionKey, int direction, Uint8List data) async {
    if (data.length < 20) {
      throw ArgumentError('Encrypted payload too short: ${data.length}');
    }
    final bd = ByteData.sublistView(data);
    final counter = bd.getUint32(0, Endian.little);
    final cipherText = data.sublist(4, data.length - 16);
    final mac = Mac(data.sublist(data.length - 16));
    final nonce = _buildNonce(counter, direction);
    final key = SecretKey(sessionKey);
    final secretBox = SecretBox(cipherText, nonce: nonce, mac: mac);
    final plaintext = await _aesGcm.decrypt(secretBox, secretKey: key);
    return (counter, Uint8List.fromList(plaintext));
  }

  /// Encrypt a confirmation message for key exchange step 3/4.
  ///
  /// Returns: [nonce:12B][ciphertext:16B][tag:16B] = 44 bytes
  static Future<Uint8List> encryptConfirmation(
      Uint8List sessionKey, Uint8List message) async {
    final key = SecretKey(sessionKey);
    final secretBox = await _aesGcm.encrypt(message, secretKey: key);
    return Uint8List.fromList([
      ...secretBox.nonce,
      ...secretBox.cipherText,
      ...secretBox.mac.bytes,
    ]);
  }

  /// Decrypt a confirmation message from key exchange step 3/4.
  ///
  /// Input: [nonce:12B][ciphertext:16B][tag:16B] = 44 bytes
  /// Returns: plaintext (16 bytes)
  static Future<Uint8List> decryptConfirmation(
      Uint8List sessionKey, Uint8List data) async {
    if (data.length < 44) {
      throw ArgumentError('Confirmation too short: ${data.length}');
    }
    final nonce = data.sublist(0, 12);
    final cipherText = data.sublist(12, data.length - 16);
    final mac = Mac(data.sublist(data.length - 16));
    final key = SecretKey(sessionKey);
    final secretBox = SecretBox(cipherText, nonce: nonce, mac: mac);
    final plaintext = await _aesGcm.decrypt(secretBox, secretKey: key);
    return Uint8List.fromList(plaintext);
  }

  /// Build KEY_EXCHANGE step 1 payload (33 bytes).
  /// [step:u8=0x01][central_x25519_pubkey:32B]
  static Uint8List buildStep1Payload(Uint8List centralX25519Pubkey) {
    return Uint8List.fromList([keyExchangeStep1, ...centralX25519Pubkey]);
  }

  /// Parse KEY_EXCHANGE step 1 payload.
  /// Returns central_x25519_pubkey (32 bytes).
  static Uint8List parseStep1Payload(Uint8List data) {
    if (data.length < 33 || data[0] != keyExchangeStep1) {
      throw ArgumentError('Invalid step 1 payload');
    }
    return data.sublist(1, 33);
  }

  /// Build KEY_EXCHANGE step 2 payload (129 bytes).
  /// [step:u8=0x02][peripheral_x25519_pubkey:32B][ed25519_signature:64B]
  /// [peripheral_ed25519_pubkey:32B]
  static Uint8List buildStep2Payload(
    Uint8List peripheralX25519Pubkey,
    Uint8List ed25519Signature,
    Uint8List peripheralEd25519Pubkey,
  ) {
    return Uint8List.fromList([
      keyExchangeStep2,
      ...peripheralX25519Pubkey,
      ...ed25519Signature,
      ...peripheralEd25519Pubkey,
    ]);
  }

  /// Parse KEY_EXCHANGE step 2 payload.
  /// Returns (peripheral_x25519_pubkey, ed25519_signature, peripheral_ed25519_pubkey).
  static (Uint8List, Uint8List, Uint8List) parseStep2Payload(Uint8List data) {
    if (data.length < 129 || data[0] != keyExchangeStep2) {
      throw ArgumentError('Invalid step 2 payload');
    }
    return (
      data.sublist(1, 33),
      data.sublist(33, 97),
      data.sublist(97, 129),
    );
  }

  /// Build KEY_EXCHANGE step 3 payload (45 bytes).
  /// [step:u8=0x03][nonce:12B][ciphertext:16B][tag:16B]
  static Uint8List buildStep3Payload(Uint8List confirmationEncrypted) {
    return Uint8List.fromList([keyExchangeStep3, ...confirmationEncrypted]);
  }

  /// Parse KEY_EXCHANGE step 3 payload.
  /// Returns the encrypted confirmation (44 bytes).
  static Uint8List parseStep3Payload(Uint8List data) {
    if (data.length < 45 || data[0] != keyExchangeStep3) {
      throw ArgumentError('Invalid step 3 payload');
    }
    return data.sublist(1, 45);
  }

  /// Build KEY_EXCHANGE step 4 payload (45 bytes).
  /// [step:u8=0x04][nonce:12B][ciphertext:16B][tag:16B]
  static Uint8List buildStep4Payload(Uint8List confirmationEncrypted) {
    return Uint8List.fromList([keyExchangeStep4, ...confirmationEncrypted]);
  }

  /// Parse KEY_EXCHANGE step 4 payload.
  /// Returns the encrypted confirmation (44 bytes).
  static Uint8List parseStep4Payload(Uint8List data) {
    if (data.length < 45 || data[0] != keyExchangeStep4) {
      throw ArgumentError('Invalid step 4 payload');
    }
    return data.sublist(1, 45);
  }
}

/// Encrypt/decrypt with counter management and replay detection.
class BlerpcCryptoSession {
  final Uint8List _sessionKey;

  /// TX counter, visible for testing.
  int txCounter = 0;
  int _rxCounter = 0;
  bool _rxFirstDone = false;
  final int _txDirection;
  final int _rxDirection;

  BlerpcCryptoSession(this._sessionKey, {required bool isCentral})
      : _txDirection = isCentral ? directionC2P : directionP2C,
        _rxDirection = isCentral ? directionP2C : directionC2P;

  /// Encrypt plaintext with auto-incrementing TX counter.
  Future<Uint8List> encrypt(Uint8List plaintext) async {
    if (txCounter >= 0xFFFFFFFF) {
      throw StateError('TX counter overflow: session must be rekeyed');
    }
    final encrypted = await BlerpcCrypto.encryptCommand(
        _sessionKey, txCounter, _txDirection, plaintext);
    txCounter++;
    return encrypted;
  }

  /// Decrypt data with replay detection on RX counter.
  Future<Uint8List> decrypt(Uint8List data) async {
    final (counter, plaintext) =
        await BlerpcCrypto.decryptCommand(_sessionKey, _rxDirection, data);
    if (_rxFirstDone && counter <= _rxCounter) {
      throw StateError('Replay detected: counter=$counter');
    }
    _rxCounter = counter;
    _rxFirstDone = true;
    return plaintext;
  }
}

/// Central-side key exchange state machine.
///
/// Usage:
///   final kx = CentralKeyExchange();
///   final step1 = await kx.start();           // send to peripheral
///   final step3 = await kx.processStep2(s2);  // send to peripheral
///   final session = await kx.finish(s4);       // BlerpcCryptoSession
class CentralKeyExchange {
  SimpleKeyPair? _x25519KeyPair;
  Uint8List? _x25519Pubkey;
  Uint8List? _sessionKey;
  int _state = 0;

  /// Generate ephemeral X25519 keypair and return step 1 payload.
  Future<Uint8List> start() async {
    if (_state != 0) throw StateError('Invalid state for start()');
    final (kp, pub) = await BlerpcCrypto.generateX25519KeyPair();
    _x25519KeyPair = kp;
    _x25519Pubkey = pub;
    _state = 1;
    return BlerpcCrypto.buildStep1Payload(pub);
  }

  /// Parse step 2, verify signature, derive session key, return step 3 payload.
  Future<Uint8List> processStep2(
    Uint8List step2Payload, {
    bool Function(Uint8List)? verifyKeyCb,
  }) async {
    if (_state != 1) throw StateError('Invalid state for processStep2()');

    final (periphX25519Pub, signature, periphEd25519Pub) =
        BlerpcCrypto.parseStep2Payload(step2Payload);

    final signMsg = Uint8List.fromList([..._x25519Pubkey!, ...periphX25519Pub]);
    final valid =
        await BlerpcCrypto.ed25519Verify(periphEd25519Pub, signMsg, signature);
    if (!valid) {
      throw ArgumentError('Ed25519 signature verification failed');
    }

    if (verifyKeyCb != null && !verifyKeyCb(periphEd25519Pub)) {
      throw ArgumentError('Peripheral key rejected by verify callback');
    }

    final sharedSecret =
        await BlerpcCrypto.x25519SharedSecret(_x25519KeyPair!, periphX25519Pub);
    _sessionKey = await BlerpcCrypto.deriveSessionKey(
        sharedSecret, _x25519Pubkey!, periphX25519Pub);

    final encryptedConfirm =
        await BlerpcCrypto.encryptConfirmation(_sessionKey!, confirmCentral);
    _state = 2;
    return BlerpcCrypto.buildStep3Payload(encryptedConfirm);
  }

  /// Parse step 4, verify peripheral confirmation, return session.
  Future<BlerpcCryptoSession> finish(Uint8List step4Payload) async {
    if (_state != 2) throw StateError('Invalid state for finish()');
    final encryptedPeriph = BlerpcCrypto.parseStep4Payload(step4Payload);
    final plaintext =
        await BlerpcCrypto.decryptConfirmation(_sessionKey!, encryptedPeriph);
    if (!_listEquals(plaintext, confirmPeripheral)) {
      throw ArgumentError('Peripheral confirmation mismatch');
    }
    return BlerpcCryptoSession(_sessionKey!, isCentral: true);
  }
}

/// Peripheral-side key exchange state machine.
///
/// Usage:
///   final kx = PeripheralKeyExchange(ed25519PrivKey);
///   final step2 = await kx.processStep1(s1);           // send to central
///   final (step4, session) = await kx.processStep3(s3); // send + session
class PeripheralKeyExchange {
  final SimpleKeyPairData _ed25519PrivKey;
  final Uint8List _ed25519PubKey;
  Uint8List? _sessionKey;
  int _state = 0;

  PeripheralKeyExchange(this._ed25519PrivKey)
      : _ed25519PubKey = Uint8List.fromList(_ed25519PrivKey.publicKey.bytes);

  /// Visible for testing.
  Uint8List? get sessionKey => _sessionKey;

  /// Parse step 1, generate ephemeral X25519 keypair, sign, derive session key,
  /// return step 2 payload.
  Future<Uint8List> processStep1(Uint8List step1Payload) async {
    if (_state != 0) throw StateError('Invalid state for processStep1()');
    final centralX25519Pub = BlerpcCrypto.parseStep1Payload(step1Payload);

    final (x25519KeyPair, x25519Pub) =
        await BlerpcCrypto.generateX25519KeyPair();

    final signMsg = Uint8List.fromList([...centralX25519Pub, ...x25519Pub]);
    final signature = await BlerpcCrypto.ed25519Sign(_ed25519PrivKey, signMsg);

    final sharedSecret =
        await BlerpcCrypto.x25519SharedSecret(x25519KeyPair, centralX25519Pub);
    _sessionKey = await BlerpcCrypto.deriveSessionKey(
        sharedSecret, centralX25519Pub, x25519Pub);

    _state = 1;
    return BlerpcCrypto.buildStep2Payload(x25519Pub, signature, _ed25519PubKey);
  }

  /// Parse step 3, verify confirmation, return (step4Payload, session).
  Future<(Uint8List, BlerpcCryptoSession)> processStep3(
      Uint8List step3Payload) async {
    if (_state != 1) throw StateError('Invalid state for processStep3()');
    final encrypted = BlerpcCrypto.parseStep3Payload(step3Payload);
    final plaintext =
        await BlerpcCrypto.decryptConfirmation(_sessionKey!, encrypted);
    if (!_listEquals(plaintext, confirmCentral)) {
      throw ArgumentError('Central confirmation mismatch');
    }

    final encryptedConfirm =
        await BlerpcCrypto.encryptConfirmation(_sessionKey!, confirmPeripheral);
    final step4 = BlerpcCrypto.buildStep4Payload(encryptedConfirm);
    final session = BlerpcCryptoSession(_sessionKey!, isCentral: false);

    return (step4, session);
  }

  /// Dispatch a key exchange payload by step byte.
  ///
  /// Returns (responsePayload, sessionOrNull).
  Future<(Uint8List, BlerpcCryptoSession?)> handleStep(
      Uint8List payload) async {
    if (payload.isEmpty) {
      throw ArgumentError('Empty key exchange payload');
    }

    final step = payload[0];
    if (step == keyExchangeStep1) {
      if (_state != 0) throw StateError('Invalid state for step 1');
      final response = await processStep1(payload);
      return (response, null);
    } else if (step == keyExchangeStep3) {
      if (_state != 1) throw StateError('Invalid state for step 3');
      final (step4, session) = await processStep3(payload);
      return (step4, session);
    } else {
      throw ArgumentError(
          'Invalid key exchange step: 0x${step.toRadixString(16).padLeft(2, '0')}');
    }
  }

  /// Reset key exchange state for new connection.
  void reset() {
    _state = 0;
    _sessionKey = null;
  }
}

/// Perform the 4-step central key exchange using send/receive callbacks.
Future<BlerpcCryptoSession> centralPerformKeyExchange({
  required Future<void> Function(Uint8List) send,
  required Future<Uint8List> Function() receive,
  bool Function(Uint8List)? verifyKeyCb,
}) async {
  final kx = CentralKeyExchange();

  // Step 1: Send central's ephemeral public key
  final step1 = await kx.start();
  await send(step1);

  // Step 2: Receive peripheral's response
  final step2 = await receive();

  // Step 2 -> Step 3: Verify and produce confirmation
  final step3 = await kx.processStep2(step2, verifyKeyCb: verifyKeyCb);
  await send(step3);

  // Step 4: Receive peripheral's confirmation
  final step4 = await receive();

  return kx.finish(step4);
}

bool _listEquals(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
