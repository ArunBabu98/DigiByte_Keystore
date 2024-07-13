import 'package:bitcoin_flutter/bitcoin_flutter.dart';

NetworkType digibyte = NetworkType(
    messagePrefix: '\x18DigiByte Signed Message:\n',
    bech32: 'dgb',
    bip32: Bip32Type(public: 0x049d7cb2, private: 0x049d7878),
    pubKeyHash: 0x1e,
    scriptHash: 0x3F,
    wif: 0x80);
