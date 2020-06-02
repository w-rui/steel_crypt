//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Create symmetric encryption machine (Crypt).
class AesCrypt {
  core.String _mode;
  Uint8List _key32;
  dynamic _encrypter;
  String _paddingName;

  ///Get this AesCrypt's key;
  Uint8List get key {
    return _key32;
  }

  ///Get this AesCrypt's type of padding.
  String get padding {
    return _paddingName;
  }

  ///Get this AesCrypt's mode of AES.
  String get mode {
    return _mode;
  }

  ///Creates 'Crypt', serves as encrypter/decrypter of text.
  AesCrypt(Uint8List inKey32,
      [core.String intype = 'gcm', core.String padding = 'pkcs7']) {
    _mode = intype;
    _key32 = inKey32;
    _paddingName = padding;

    if (_mode == 'cbc') {
      _encrypter = CBCBlockCipher(AESFastEngine());
    } else if (_mode == 'sic') {
      _paddingName = 'none';
      _encrypter = SICStreamCipher(AESFastEngine());
    } else if (_mode == 'cfb-64') {
      _encrypter = CFBBlockCipher(AESFastEngine(), 64);
    } else if (_mode == 'ctr') {
      _paddingName = 'none';
      _encrypter = CTRStreamCipher(AESFastEngine());
    } else if (_mode == 'ecb') {
      _encrypter = ECBBlockCipher(AESFastEngine());
    } else if (_mode == 'ofb-64') {
      _encrypter = OFBBlockCipher(AESFastEngine(), 64);
    } else if (_mode == 'gctr') {
      _encrypter = GCTRBlockCipher(AESFastEngine());
    } else if (_mode == 'gcm') {
      _encrypter = GCMBlockCipher(AESFastEngine());
    } else {
      throw ArgumentError('invalid mode');
    }
  }

  ///Encrypt (with iv) and return in base 64.
  Uint8List encrypt(Uint8List input, [Uint8List iv]) {
    iv = iv ?? Uint8List(0);
    if (_mode != 'ecb') {
      if (_paddingName == 'none') {
        var localKey = _key32;
        var localIV = iv;
        var params =
        ParametersWithIV<KeyParameter>(KeyParameter(localKey), localIV);
        _encrypter..init(true, params);
        var inter = _encrypter.process(input) as Uint8List;
        return inter;
      } else {
        var key = _key32;
        var ivLocal = iv;
        CipherParameters params = PaddedBlockCipherParameters(
            ParametersWithIV<KeyParameter>(KeyParameter(key), ivLocal), null);
        var cipher = PaddedBlockCipher(
            'AES/' + _mode.toUpperCase() + '/' + _paddingName.toUpperCase());
        cipher..init(true, params);
        var inter = cipher.process(input);
        return inter;
      }
    } else {
      var key = _key32;
      CipherParameters params =
      PaddedBlockCipherParameters(KeyParameter(key), null);
      var cipher = PaddedBlockCipher(
          'AES/' + _mode.toUpperCase() + '/' + _paddingName.toUpperCase());
      cipher..init(true, params);
      var inter = cipher.process(input);
      return inter;
    }
  }

  ///Decrypt base 64 (with iv) and return original.
  Uint8List decrypt(Uint8List encrypted, [Uint8List iv]) {
    iv = iv ?? Uint8List(0);

    if (_mode != 'ecb') {
      if (_paddingName == 'none') {
        var localKey = _key32;
        var localIV = iv;
        var localInput = encrypted;
        var params =
        ParametersWithIV<KeyParameter>(KeyParameter(localKey), localIV);
        _encrypter..init(false, params);
        var inter = _encrypter.process(localInput);
        return inter as Uint8List;
      } else {
        var key = _key32;
        var ivLocal = iv;
        CipherParameters params = PaddedBlockCipherParameters(
            ParametersWithIV(KeyParameter(key), ivLocal), null);
        var cipher = PaddedBlockCipher(
            'AES/' + _mode.toUpperCase() + '/' + _paddingName.toUpperCase());
        cipher..init(false, params);
        var inter = cipher.process(encrypted);
        return inter;
      }
    } else {
      var key = _key32;
      CipherParameters params =
      PaddedBlockCipherParameters(KeyParameter(key), null);
      var cipher = PaddedBlockCipher(
          'AES/' + _mode.toUpperCase() + '/' + _paddingName.toUpperCase());
      cipher..init(false, params);
      var inter = cipher.process(encrypted);
      return inter;
    }
  }
}
