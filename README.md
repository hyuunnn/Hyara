# Hyara (IDA Plugin)
Hyara is IDA Plugin that provides convenience when writing yararule.

You can designate the start and end addresses to automatically create rules.

It was created based on GUI, and adding features and improvements are currently underway.

## Test Environment
IDA Pro 7.0

Python 2.7.13

capstone 3.0.5rc2

keystone 0.9.1

yara-python 3.7.0

pefile 2017.11.5

Pillow 5.2.0

## Installation

$ pip install -r requirements.txt

(if error occurs during the installation of capstone or keystone, go to the installation page for each libarary and use the installation files)

(https://www.capstone-engine.org/download.html)

(http://www.keystone-engine.org/download/)

copy Hyara.py to (IDA Pro installation directory)/plugins

copy assembler_disassembler.py to (IDA Pro installation directory)/plugins

## Hotkeys
Hyara: Ctrl + Shift + Y

assembler_disassembler: Ctrl + Shift + A

## Features
### Hyara start screen and 2 options
- When you run Hyara, it aligns to the right like the below picture and the output window is aligned to the left.
- Select/Exit button uses IDAViewWrapper api to get the clicked address in IDA View. After done, you have to press it again to finish.
- After specifying the address, press the "Make" button to show the specified hexadecimal or strings as a result.
- When you click "Save", those results will be saved in the table below.
- Press "Export Yara Rule" to finally create the yararule using variables stored in the privious step.
- The comment option on the upper right side annotates the assemblies nicely.
- The wildcard option works but further development is still on going.
<img src="images/Hyara_1.png" width="100%">

### String option
- This option is to extract strings within the range user specified.
<img src="images/Hyara_2.png" width="100%">
<img src="images/Hyara__5.png" width="100%">
<img src="images/Hyara_6.png" width="100%">

### YaraChecker
- You can test the yararule you write on the fly.
- The recursive feature is applied by default, so you should carefully set the path.
<img src="images/Hyara_3.png" width="100%">

### YaraIcon
- "YaraIcon" provides the convenience when you write the rule with Icon.
<img src="images/Hyara_4.png" width="100%">

### assem_disassembler
- When creating rules, be sure to check how the assembly changes when you use wildcards.
- Normally people uses website to convert assembly but you can check it by using this feature.
<img src="images/assem_disassembler.png" width="100%">


### Description of "old_version"
- old_version/Hyara_Using_simplecustviewer_Choose.py)
- This version uses Choose and simplecustviewer.
<img src="images/Hyara_old.png" width="100%">

## Special Thanks

- <a href="https://twitter.com/kjkwak12">kjkwak12</a>