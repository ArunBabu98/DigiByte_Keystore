import 'dart:typed_data';

import 'package:hex/hex.dart';

/// Converts a hexadecimal string to a Uint8List.
Uint8List convertHex(String seedHex) {
  List<int> bytes = [];
  for (int i = 0; i < seedHex.length; i += 2) {
    String hex = seedHex.substring(i, i + 2);
    bytes.add(int.parse(hex, radix: 16));
  }
  return Uint8List.fromList(bytes);
}

/// Extracts the least significant digit from a hexadecimal string.
String leastSignificantDigit(String hexKey) {
  String lastChar = hexKey[hexKey.length - 1];
  int lsd = int.parse(lastChar, radix: 16) % 10;
  return lsd.toString();
}

/// XORs the given private key with the provided least significant bits.
String xorWithLsb(String privateKey, List<int> lsbs) {
  final privateKeyBytes = HEX.decode(privateKey);
  final xorResult = List<int>.generate(
    privateKeyBytes.length,
    (i) => privateKeyBytes[i] ^ lsbs[i],
  );
  return HEX.encode(Uint8List.fromList(xorResult));
}

class Debug {
  late bool flag;
  Debug({required this.flag});

  log(String value) {
    if (flag) {
      print(value);
    }
  }
}
