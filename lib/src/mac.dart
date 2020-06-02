//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Class containing hashing for Message Authentication Codes.
class MacCrypt {
  String _type;
  dynamic _mac;

  MacCrypt(Uint8List key, [String inType = 'CMAC', String algo = 'gcm']) {
    _type = inType;
    if (_type == 'HMAC') {
      _mac = _HMAC(key, algo);
    } else if (_type == 'CMAC') {
      _mac = _CMAC(key, algo);
    }
  }

  ///Process and hash string
  Uint8List process(Uint8List input) {
    return _mac.process(input) as Uint8List;
  }

  ///Check if plaintext matches previously hashed text
  bool check(Uint8List plain, Uint8List processed) {
    return _mac.check(plain, processed) as bool;
  }
}

class _HMAC {
  KeyParameter _listkey;
  String _algorithm;

  _HMAC(Uint8List key, String algo) {
    _listkey = KeyParameter(key);
    _algorithm = algo;
  }

  Uint8List process(Uint8List bytes) {
    final _tmp = HMac(Digest(_algorithm), 128)
      ..init(_listkey);
    return _tmp.process(bytes);
  }

  bool check(Uint8List plain, Uint8List processed) {
    var newhash = process(plain);
    return newhash == processed;
  }
}

class _CMAC {
  KeyParameter _listkey;
  String _algorithm;

  _CMAC(Uint8List key, algo) {
    _listkey = KeyParameter(key);
    _algorithm = algo as String;
  }

  Uint8List process(Uint8List input) {
    final _tmp = CMac(BlockCipher('AES/' + _algorithm.toUpperCase()), 64)
      ..init(_listkey);
    return _tmp.process(input);
  }

  bool check(Uint8List plain, Uint8List processed) {
    var newhash = process(plain);
    return newhash == processed;
  }
}
