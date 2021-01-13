# Welcome to Hyara 👋

![Version](https://img.shields.io/badge/version-2.0-blue.svg?cacheSeconds=2592000)

> Hyara is a Yara rule generator that supports various disassemblers.
> 
> The plugin is currently undergoing a major revision!

- [Demo video](https://youtu.be/zgL4BkQJZ-w)

## Features

- GUI-based
- Supports BinaryNinja, Cutter, and IDA
- YaraChecker (WIP)
  - Tests the yararule on the fly
  - <img src="images/Hyara_3.png" width="100%">
- YaraDetector (WIP)
  - Shows which part is detected in the sample loaded to IDA, and when "Address" is clicked, it moves to the corresponding address on the IDA View.
  - <img src="images/Hyara__7.png" width="100%">
- YaraIcon (WIP)
  - Creates yara rules for icon resources embedded in the PE
  - <img src="images/Hyara_4.png" width="100%">

## Installation

### IDA Pro & BinaryNinja

```bash
pip install -r requirements.txt
```

- IDA Pro
  - Activate via Edit -> Plugins -> Hyara (or CTRL+SHIFT+Y)
- BinaryNinja
  - <img src="images/binja_0.png" width="100%">

### Cutter

```bash
python3 -m pip install -I -t $cutter_dir\$cutter_python_version\site-packages -r requirements.txt
```

<img src="images/cutter__0.png" width="100%">

## Instructions

### Start Screen and Options

- When you run Hyara, it docks itself to the right and docks the output window to the left.
- `Select/Exit` button uses the IDAViewWrapper API to get the clicked address in IDA View.
  - After you've selected the relevant addresses, click it again to toggle the selection behavior.
- The results are saved in the table below when you click `Save`.
- After specifying the address, press the `Make` button to show the specified hexadecimal or strings as a result.
- Double-clicking the table clears all the existing rules.
- `Export Yara Rule`
  - Exports the previously created yara rules.
<img src="images/Hyara__1.png" width="100%">

- `Comment Option`
  - Annotates the instructions next to the condition rule(s.
- `Rich Header` and `imphash`
  - Adds rich header and imphash matching to the rule.
- `String option`
  - This option extracts strings within the range specified.

<img src="images/Hyara___5.png" width="100%">
<img src="images/Hyara_6.png" width="100%">

## Author

👤 **hyuunnn**

* Github: [@hyuunnn](https://github.com/hyuunnn)

### Special Thanks

* Twitter: <a href="https://twitter.com/kjkwak12">kjkwak12</a>
