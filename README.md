# Hyara

![Version](https://img.shields.io/badge/version-2.3-blue.svg?cacheSeconds=2592000)

![](https://github.com/hyuunnn/Hyara/blob/master/images/Hyara.gif?raw=true)

> Hyara is plugin that provides convenience when writing yararule.
> 
> The plugin is currently undergoing a major revision!

- [Demo video](https://youtu.be/zgL4BkQJZ-w)

- [IDA Plugin Contest 2018](https://hex-rays.com/contests_details/contest2018/#Hyara)

- [Hyara - Generator for YARA Rules (KOR)](https://github.com/hyuunnn/slides/blob/main/Hyara%20-%20Generator%20for%20YARA%20Rules.pdf) - 2018. 09. 16

## Instructions

### Start Screen and Options

- When you run Hyara, it docks itself to the right and docks the output window to the left.
- After specifying the address, press the `Make` button to show the specified hexadecimal or strings as a result.
- The results are saved in the table below when you click `Save`.
- If you double-click the table, you can clear the rule.
- You can modify the values to wildcards by right clicking after dragging.

![](https://github.com/hyuunnn/Hyara/blob/master/images/wildcard_0.png?raw=true)

- `Export Yara Rule`
  - Exports the previously created yara rules.

![](https://github.com/hyuunnn/Hyara/blob/master/images/Hyara_1.png?raw=true)


- `Right Click`
  - You can select either start address or end address. (IDA Pro, Cutter)

![](https://github.com/hyuunnn/Hyara/blob/master/images/Hyara_7.png?raw=true)
  
- `Comment Option`
  - Annotates the instructions next to the condition rule(s).
- `Rich Header` and `imphash`
  - Adds rich header and imphash matching to the rule.
- `String option`
  - This option extracts strings within the range specified.

![](https://github.com/hyuunnn/Hyara/blob/master/images/Hyara_3.png?raw=true)
![](https://github.com/hyuunnn/Hyara/blob/master/images/cutter_1.png?raw=true)

## Installation

### IDA Pro & BinaryNinja

- IDA Pro
  ```bash
  pip install -r requirements.txt
  ```
  - copy ``Hyara_IDA.py and hyara_lib folder`` to $ida_dir/plugins
  - Activate via Edit -> Plugins -> Hyara (or CTRL+SHIFT+Y)

- BinaryNinja
  - Just use the plugin manager!
  - Activate via View -> Other Docks -> Show Hyara

### Cutter

- Windows

Check the python version installed in the cutter and install it.

![](https://github.com/hyuunnn/Hyara/blob/master/images/cutter_0.png?raw=true)

```bash
C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python3X\\python.exe -m pip install -I -t $cutter_dir/python3X/site-packages -r requirements.txt
```

copy ``__init__.py, Hyara_Cutter.py and hyara_lib folder`` to $cutter_dir/plugins/python/Hyara

- Linux

![](https://github.com/hyuunnn/Hyara/blob/master/images/cutter_install__1.png?raw=true)

```bash
cp -r /tmp/.mount_Cutter5o3a5G/usr /root
```

Check the python version installed in the cutter and install it.

![](https://github.com/hyuunnn/Hyara/blob/master/images/cutter_01.png?raw=true)

```bash
pip3.X install -I -t /root/usr/lib/python3.X/site-packages -r /root/Hyara/requirements.txt
./Cutter-v2.0.3-x64.Linux.AppImage --pythonhome /root/usr
```

copy ``__init__.py, Hyara_Cutter.py and hyara_lib folder`` to /root/.local/share/rizin/cutter/plugins/python/Hyara

Activate via Windows -> Plugins -> Hyara

![](https://github.com/hyuunnn/Hyara/blob/master/images/cutter__0.png?raw=true)

### Ghidra (WIP)

Install <a href="https://github.com/mandiant/Ghidrathon">Ghidrathon</a> (<a href="https://youtu.be/Aatbqf6lcjU">Installation Guide</a>) to use Hyara Plugin.

```bash
pip install PySide2 or pip install PySide6
```

- Windows

copy ``Hyara_Ghidra.py and hyara_lib folder`` to ``C:\\Users\\User\\.ghidra\\.ghidra.X.X.X\\Extensions\\Ghidrathon-X.X.X\\data\\python\\``

```python
# Window -> Ghidrathon
import Hyara_Ghidra
Hyara_Ghidra.run()
```

![](https://github.com/hyuunnn/Hyara/blob/master/images/ghidra_0.png?raw=true)


## Features

- GUI-based
- Supports IDA, BinaryNinja, Cutter and Ghidra.
- YaraChecker
  - Tests the yararule on the fly.
  - ![](https://github.com/hyuunnn/Hyara/blob/master/images/Hyara_4.png?raw=true)
- YaraDetector
  - Shows which part is detected in the sample loaded to disassembler, and when "Address" is clicked, it moves to the corresponding address on the disassembler view.
  - ![](https://github.com/hyuunnn/Hyara/blob/master/images/Hyara_5.png?raw=true)
- YaraIcon
  - Creates yara rules for icon resources embedded in the PE.
  - ![](https://github.com/hyuunnn/Hyara/blob/master/images/Hyara_6.png?raw=true)

## Author

👤 **hyuunnn**

* Github: [@hyuunnn](https://github.com/hyuunnn)

### Special Thanks

* Twitter: <a href="https://twitter.com/kjkwak12">kjkwak12</a>
* Github: <a href="https://github.com/gaasedelen">gaasedelen</a> - <a href="https://github.com/hyuunnn/Hyara/blob/master/hyara_lib/integration/bn_hyara/binaryninja_api.py#L9">Link</a>
* Github: <a href="https://github.com/ITAYC0HEN">ITAYC0HEN</a> - <a href="https://github.com/hyuunnn/Hyara/pull/14">Link</a>
* Github: <a href="https://github.com/psifertex">psifertex</a> - <a href="https://github.com/hyuunnn/Hyara/pull/18">Link</a>

## Link

* <a href="https://twitter.com/cyb3rops/status/1024208220989140992">Florian Roth's Twitter</a>
* <a href="https://danielplohmann.github.io/blog/2024/03/08/malpediaflossed.html">MalpediaFLOSSed</a> - <a href="https://twitter.com/push_pnx/status/1766045950173200513">Twitter</a>
* <a href="https://cocacoding.com/papers/Automatic_Generation_of_code_based_YARA_Signatures.pdf">Automatic Generation of code-based YARA-Signatures</a>
* <a href="https://www.cocacoding.com/papers/Improving_YARA-Signator_for_effective_Generation_of_code-based_YARA-Signatures.pdf">Improving YARA-Signator for effective Generation of code-based YARA-Signatures</a>
