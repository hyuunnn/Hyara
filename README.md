## YaraGenerator (IDA Plugin)

YaraGenerator is a tool to help you make yara rule in IDA.

If you enter an address, the assembly of that address is created as a Yara rule.

Complete automation is due to the existence of false positives.

The wildcard feature is currently under study.

### [ YaraGenerator ]
<img src="images/YaraGenerator.png" width="75%">

### [ YaraChecker ]
<img src="images/YaraChecker_1.png" width="75%">
<img src="images/YaraChecker_2.png" width="75%">

### Install & Tutorial

pip install yara-python

pip install capstone-engine

pip install keystone-engine

copy YaraGenerator.py C:\Program Files\IDA 7.0\plugins

copy assembler_disassembler.py C:\Program Files\IDA 7.0\plugins

YaraGenerator HOT-KEY : Ctrl + Y

assembler_disassembler HOT-KEY: Ctrl + A

