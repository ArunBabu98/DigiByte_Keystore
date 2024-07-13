// To parse this JSON data, do
//
//     final UtxoModel = UtxoModelFromJson(jsonString);

import 'dart:convert';

List<UtxoModel> UtxoModelFromJson(String str) =>
    List<UtxoModel>.from(json.decode(str).map((x) => UtxoModel.fromJson(x)));

String UtxoModelToJson(List<UtxoModel> data) =>
    json.encode(List<dynamic>.from(data.map((x) => x.toJson())));

class UtxoModel {
  UtxoModel({
    required this.txid,
    required this.vout,
    required this.value,
    required this.height,
    required this.confirmations,
    required this.address,
    required this.path,
    required this.scriptPubKey,
  });

  String txid;
  int vout;
  String value;
  int? height;
  int confirmations;
  String? address;
  String? path;
  String? scriptPubKey;

  factory UtxoModel.fromJson(Map<String, dynamic> json) => UtxoModel(
        txid: json["txid"],
        vout: json["vout"],
        value: json["value"],
        height: json["height"],
        confirmations: json["confirmations"],
        address: json["address"],
        path: json["path"],
        scriptPubKey: json["scriptPubKey"],
      );

  Map<String, dynamic> toJson() => {
        "txid": txid,
        "vout": vout,
        "value": value,
        "height": height,
        "confirmations": confirmations,
        "address": address,
        "path": path,
        "scriptPubKey": scriptPubKey,
      };
}
