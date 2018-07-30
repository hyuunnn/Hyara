# Hyara (IDA Plugin)
Hyara is IDA Plugin that provides convenience when writing yararule.
You can designate the start and end addresses to automatically create rules.
It was created based on GUI, and adding features and improvements are currently underway.

## Test Environment
IDA Pro 7.0
Python 2.7.13

## Installation
pip install yara-python pefile pillow 
pip install capstone (https://www.capstone-engine.org/download.html)
pip install keystone-engine (http://www.keystone-engine.org/download/)

copy Hyara.py to C:\Program Files\IDA 7.0\plugins
copy assembler_disassembler.py to C:\Program Files\IDA 7.0\plugins

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
- 1번째 사진에 하나 남아있었던 string option은 아래 사진과 같이 string을 뽑아올 때 사용됩니다.
- .text section은 코드 영역이기 때문에 IDA에서 해석해주는 어셈 코드에서 "offset"이라는 문자열을 체크 한 후에 따라오는 변수의 string을 가져오고, .text endEA 이후는 코드 영역이 아니기 때문에 문자열을 그대로 가져오게 됩니다.
- 다양한 string을 뽑아와야 하는 경우에 활용 할 수 있습니다.
- 만약에 유니크한 문자열이지만, IDA에서 제대로 해석해주지 못할 경우 rule 작성에 편리함을 제공합니다.
<img src="images/Hyara_2.png" width="100%">

### YaraChecker
- YaraChecker는 작성된 rule을 바로 테스트 해볼 수 있는 기능입니다.
- 기본적으로 recursive 기능이 적용되어 있으니, path 설정을 신중히 해야합니다. (IDA가 종료될 수 있음)
<img src="images/Hyara_3.png" width="100%">

### YaraIcon
- YaraIcon은 Icon으로 rule을 작성할 때 편리함을 제공하는 기능입니다.
- 예를 들어 ransomware는 무수히 많이 있고, 변종도 존재합니다. 하지만 악성코드에서 사용되는 Icon으로 rule을 작성하여 Icon 유사도를 측정할 수 있습니다.
<img src="images/Hyara_4.png" width="100%">

### assem_disassembler
- yara rule 작성에 도우미 역할을 해주는 간단한 플러그인입니다.
- rule 작성 시 와일드카드를 사용 할 때 어셈코드가 어떻게 변하는지 확인한 후에 작성해야합니다.
- 주로 변환해주는 웹 사이트를 사용했었는데, 도구를 사용하면 바로 확인이 가능합니다.
<img src="images/assem_disassembler.png" width="100%">


### Description of "old_version"
- IDAViewWrapper를 사용하기 전에 만든 기능입니다. (old_version/Hyara_Using_simplecustviewer_Choose.py)
- Choose와 simplecustviewer를 이용하여 주소 클릭으로 Address를 지정해줍니다.
<img src="images/Hyara_old.png" width="100%">
