// To parse this JSON data, do
//
//     final encodedKeyModel = encodedKeyModelFromJson(jsonString);

import 'dart:convert';

EncodedKeyModel encodedKeyModelFromJson(String str) =>
    EncodedKeyModel.fromJson(json.decode(str));

String encodedKeyModelToJson(EncodedKeyModel data) =>
    json.encode(data.toJson());

class EncodedKeyModel {
  dynamic error;
  String? id;
  List<String> result;

  EncodedKeyModel({
    this.error,
    this.id,
    required this.result,
  });

  factory EncodedKeyModel.fromJson(Map<String, dynamic> json) =>
      EncodedKeyModel(
        error: json["error"],
        id: json["id"],
        result: json["result"] == null
            ? []
            : List<String>.from(json["result"]!.map((x) => x)),
      );

  Map<String, dynamic> toJson() => {
        "error": error,
        "id": id,
        "result": result,
      };
}
