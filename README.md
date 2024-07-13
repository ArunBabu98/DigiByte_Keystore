# DigiByte_Keystore

The DigiByte Keystore Library provides a unique and secure mechanism for encrypted storage by leveraging the DigiByte blockchain. It allows you to store encrypted keys directly in the blockchain using the OP_RETURN field of DigiByte transactions. This approach ensures a highly secure and decentralized method for key storage, combining the robustness of blockchain technology with advanced encryption techniques.

- Secure Key Storage: Encrypt and store keys in the DigiByte blockchain, ensuring high security and immutability.

- Blockchain-Based Storage: Utilize the decentralized nature of the DigiByte blockchain to store encrypted keys, removing the need for traditional centralized storage solutions.

- OP_RETURN Field Utilization: Leverage the OP_RETURN field in DigiByte transactions for efficient and secure key storage.

- Mnemonic Access: Users can access their encrypted keys on the blockchain using their mnemonic key phrase, ensuring secure and exclusive access.

- Scalability: This technology can be scaled for other purposes, although it is limited by the maximum space of the OP_RETURN field.

## Getting Started

To get started with the DigiByte Keystore Library, follow the installation instructions and refer to the usage examples provided in the documentation.

### Installation

Add the following to your 'pubspec.yaml' file:

```
  digibyte_keystore:
    git:
      url: https://github.com/ArunBabu98/DigiByte_Keystore
      ref: master
```

### Usage

Here is a simple example to demonstrate how to use the DigiByte Keystore Library:

```
import 'package:digibyte_keystore/digibyte_keystore.dart';

void main() {
  String seed = "your-seed-hex-string";
  DigiByteKeystore keystore = DigiByteKeystore.fromSeed(
    'https://digiassetcore.example.com',
    seed,
    20,
    log: true,
  );

  // Encrypt and store a private key
  String privateKey = "your-private-key-hex-string";
  String utxoWif = "your-utxo-wif";
  Map<String, dynamic> utxo = {
    "txid": "your-transaction-id",
    "vout": 0,
    "value": "10000000",
  };

  keystore.generateEncryption(privateKey, utxoWif, utxo).then((result) {
    print("Raw TX: ${result['rawTX']}");
    print("OP Data: ${result['opData']}");
  }).catchError((e) {
    print("Error: $e");
  });
}


```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.