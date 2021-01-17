# Hyara

![Version](https://img.shields.io/badge/version-2.0-blue.svg?cacheSeconds=2592000)

<img src="images/Hyara.gif" width="100%">

> Hyara is plugin that provides convenience when writing yararule.
> 
> The plugin is currently undergoing a major revision!

- [Demo video](https://youtu.be/zgL4BkQJZ-w)

## Instructions

### Start Screen and Options

- When you run Hyara, it docks itself to the right and docks the output window to the left.
- After specifying the address, press the `Make` button to show the specified hexadecimal or strings as a result.
- The results are saved in the table below when you click `Save`.
- If you double-click the table, you can clear the rule.
- `Export Yara Rule`
  - Exports the previously created yara rules.
<img src="images/Hyara_1.png" width="100%">

- `Comment Option`
  - Annotates the instructions next to the condition rule(s).
- `Rich Header` and `imphash`
  - Adds rich header and imphash matching to the rule.
- `String option`
  - This option extracts strings within the range specified.

<img src="images/Hyara_3.png" width="100%">
<img src="images/cutter_1.png" width="100%">

## Installation

### IDA Pro & BinaryNinja

```bash
pip install -r requirements.txt
```
- IDA Pro
  - copy ``Hyara_IDA.py and hyara_lib folder`` to $ida_dir/plugins
  - Activate via Edit -> Plugins -> Hyara (or CTRL+SHIFT+Y)
- BinaryNinja
  - copy ``Hyara_BinaryNinja.py and hyara_lib folder`` to BinaryNinja Plugin directory
  - Activate via View -> Show Hyara

### Cutter

### Windows
```bash
python3 -m pip install -I -t $cutter_dir/$cutter_python_version/site-packages -r requirements.txt
```

### Linux

<img src="images/cutter_install_1.png" width="100%">

```bash
mv /tmp/.mount_CutterEgQh2i/usr .
pip3 install -I -t usr/lib/python3.6/site-packages/ -r /root/Hyara/requirements.txt
./Cutter-v1.12.0-x64.Linux.AppImage --pythonhome /root/usr
```

copy ``__init__.py, Hyara_Cutter.py and hyara_lib folder`` to $cutter_plugin_dir/python/Hyara

Activate via Windows -> Plugins -> Hyara

<img src="images/cutter__0.png" width="100%">

## Features

- GUI-based
- Supports BinaryNinja, Cutter, and IDA
- YaraChecker
  - Tests the yararule on the fly
  - <img src="images/Hyara_4.png" width="100%">
- YaraDetector
  - Shows which part is detected in the sample loaded to disassembler, and when "Address" is clicked, it moves to the corresponding address on the disassembler view.
  - <img src="images/Hyara_5.png" width="100%">
- YaraIcon
  - Creates yara rules for icon resources embedded in the PE.
  - <img src="images/Hyara_6.png" width="100%">

## Author

👤 **hyuunnn**

* Github: [@hyuunnn](https://github.com/hyuunnn)

### Special Thanks

* Twitter: <a href="https://twitter.com/kjkwak12">kjkwak12</a>
