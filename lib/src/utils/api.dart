import 'dart:convert';
import 'package:http/http.dart' as http;
import '../models/encodedKeyModel.dart';

Future<List> getEncodedKeys(
    List<String> addresses, String digiassetNode) async {
  final headers = {'Content-Type': 'application/json'};
  final body = json.encode({
    "jsonrpc": "2.0",
    "method": "getencryptedkey",
    "params": [addresses]
  });

  final response = await http.post(
    Uri.parse(digiassetNode),
    headers: headers,
    body: body,
  );

  if (response.statusCode == 200) {
    try {
      final encodedKeyModel = encodedKeyModelFromJson(response.body);
      return [true, encodedKeyModel];
    } catch (e) {
      return [false, 'Failed to parse response: $e'];
    }
  } else {
    return [false, 'Server error: ${response.body}'];
  }
}
