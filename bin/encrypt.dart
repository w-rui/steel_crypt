import 'package:steel_crypt/steel_crypt.dart';


import 'package:args/args.dart';

void main(List<String> args) {
  final argParser = ArgParser();

  argParser.addOption('text',
      abbr: 't', defaultsTo: '', help: 'Input the word to be encrypted here...');

  argParser.addOption('key',
      abbr: 'k', defaultsTo: '', help: 'Input the key to encrypt the word here...');

  argParser.addOption('iv',
      abbr: 'i', defaultsTo: '', help: 'Input the IV to encrypt the word here...');

  argParser.addFlag('help',
      abbr: 'h', defaultsTo: false, help: 'Show this help message');

  final results = argParser.parse(args);

  final key = results['key'].toString();
  final input = results['text'].toString();
  final iv = results['iv'].toString();

  final help = results['help'] as bool;

  if (help) {
    return print(argParser.usage);
  }

  print(SymCrypt(key).encrypt(input, iv));
}