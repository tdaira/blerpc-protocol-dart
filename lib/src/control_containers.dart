// Factory functions for control containers.
import 'dart:typed_data';

import 'container.dart';
import 'container_types.dart';

/// Create a timeout request control container (Central -> Peripheral).
Container makeTimeoutRequest(int transactionId, {int sequenceNumber = 0}) {
  return Container(
    transactionId: transactionId,
    sequenceNumber: sequenceNumber,
    containerType: ContainerType.control,
    controlCmd: ControlCmd.timeout,
  );
}

/// Create a timeout response control container (Peripheral -> Central).
Container makeTimeoutResponse(int transactionId, int timeoutMs,
    {int sequenceNumber = 0}) {
  final payload = ByteData(2)..setUint16(0, timeoutMs, Endian.little);
  return Container(
    transactionId: transactionId,
    sequenceNumber: sequenceNumber,
    containerType: ContainerType.control,
    controlCmd: ControlCmd.timeout,
    payload: payload.buffer.asUint8List(),
  );
}

/// Create stream end container (Central -> Peripheral).
Container makeStreamEndC2P(int transactionId, {int sequenceNumber = 0}) {
  return Container(
    transactionId: transactionId,
    sequenceNumber: sequenceNumber,
    containerType: ContainerType.control,
    controlCmd: ControlCmd.streamEndC2P,
  );
}

/// Create stream end container (Peripheral -> Central).
Container makeStreamEndP2C(int transactionId, {int sequenceNumber = 0}) {
  return Container(
    transactionId: transactionId,
    sequenceNumber: sequenceNumber,
    containerType: ContainerType.control,
    controlCmd: ControlCmd.streamEndP2C,
  );
}

/// Create a capabilities request control container (Central -> Peripheral).
///
/// 6-byte payload: [max_req:u16LE][max_resp:u16LE][flags:u16LE]
Container makeCapabilitiesRequest(
  int transactionId, {
  int maxRequestPayloadSize = 0,
  int maxResponsePayloadSize = 0,
  int flags = 0,
  int sequenceNumber = 0,
}) {
  final payload = ByteData(6)
    ..setUint16(0, maxRequestPayloadSize, Endian.little)
    ..setUint16(2, maxResponsePayloadSize, Endian.little)
    ..setUint16(4, flags, Endian.little);
  return Container(
    transactionId: transactionId,
    sequenceNumber: sequenceNumber,
    containerType: ContainerType.control,
    controlCmd: ControlCmd.capabilities,
    payload: payload.buffer.asUint8List(),
  );
}

/// Create a capabilities response control container (Peripheral -> Central).
///
/// 6-byte payload: [max_req:u16LE][max_resp:u16LE][flags:u16LE]
Container makeCapabilitiesResponse(
  int transactionId, {
  required int maxRequestPayloadSize,
  required int maxResponsePayloadSize,
  int flags = 0,
  int sequenceNumber = 0,
}) {
  final payload = ByteData(6)
    ..setUint16(0, maxRequestPayloadSize, Endian.little)
    ..setUint16(2, maxResponsePayloadSize, Endian.little)
    ..setUint16(4, flags, Endian.little);
  return Container(
    transactionId: transactionId,
    sequenceNumber: sequenceNumber,
    containerType: ContainerType.control,
    controlCmd: ControlCmd.capabilities,
    payload: payload.buffer.asUint8List(),
  );
}

/// Create an error control container (Peripheral -> Central).
Container makeErrorResponse(int transactionId, int errorCode,
    {int sequenceNumber = 0}) {
  return Container(
    transactionId: transactionId,
    sequenceNumber: sequenceNumber,
    containerType: ContainerType.control,
    controlCmd: ControlCmd.error,
    payload: Uint8List.fromList([errorCode]),
  );
}

/// Create a key exchange control container.
Container makeKeyExchange(int transactionId, Uint8List payload,
    {int sequenceNumber = 0}) {
  return Container(
    transactionId: transactionId,
    sequenceNumber: sequenceNumber,
    containerType: ContainerType.control,
    controlCmd: ControlCmd.keyExchange,
    payload: payload,
  );
}
