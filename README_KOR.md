# Hyara (IDA Plugin)

Hyara는 IDA를 활용하여 yara rule을 작성할 때 편리함을 제공하는 도구입니다.

시작 주소와 끝 주소를 입력하면 자동으로 rule을 작성해줍니다.

GUI로 제작되었으며, 기능과 개선은 현재 진행 중에 있습니다.

## 테스트 환경

IDA Pro 7.0

Python 2.7.13

## 설치 방법

pip install yara-python pefile pillow 

pip install capstone 또는 모듈 인스톨러 설치 (https://www.capstone-engine.org/download.html)

pip install keystone-engine 또는 모듈 인스톨러 설치 (http://www.keystone-engine.org/download/)

copy Hyara.py C:\Program Files\IDA 7.0\plugins

copy assembler_disassembler.py C:\Program Files\IDA 7.0\plugins

## 핫 키

Hyara HOT-KEY : Ctrl + Shift + Y

assembler_disassembler HOT-KEY: Ctrl + Shift + A

## 기능
- Hyara 플러그인을 실행하면 사진과 같이 오른쪽에 정렬시켜주고, Output window는 왼쪽으로 정렬하게 됩니다.
- Select / Exit는 IDAViewWrapper를 이용하여 IDA View-A에서 클릭된 주소를 가져옵니다. 사용이 끝난 후에는 Unbind를 시켜야하기 때문에 종료를 하기 위해 한번 더 눌러줘야합니다.
- 주소를 지정한 후 Make 버튼을 누르면 지정한 특정 부분을 결과로 보여주고, Save를 누르면 아래 Table에 저장이 됩니다. Export Yara Rule을 누르면 저장된 rule을 형식에 맞게 만들어줍니다.
- 오른쪽 상단에 comment option은 어셈 코드를 이쁘게 주석을 달아주는 기능, wildcard option은 아직 미완성이지만 와일드카드 처리를 경우에 따라 해주는 기능입니다.
<img src="images/Hyara_1.png" width="100%">

- 1번째 사진에 하나 남아있었던 string option은 아래 사진과 같이 string을 뽑아올 때 사용됩니다.
- .text section은 코드 영역이기 때문에 IDA에서 해석해주는 어셈 코드에서 "offset"이라는 문자열을 체크 한 후에 따라오는 변수의 string을 가져오고, .text endEA 이후는 코드 영역이 아니기 때문에 문자열을 그대로 가져오게 됩니다.
- 이 기능은 유니크한 문자열이지만, IDA에서 코드 영역으로 해석해주지 못할 경우 rule 작성에 편리함을 제공합니다.
<img src="images/Hyara_2.png" width="100%">

- YaraChecker는 작성된 rule을 바로 테스트 해볼 수 있는 기능입니다.
- 기본적으로 recursive 기능이 적용되어 있으니, path 설정을 신중히 해야합니다. (IDA가 종료될 수 있음)
<img src="images/Hyara_3.png" width="100%">

- YaraIcon은 Icon으로 rule을 작성할 때 편리함을 제공하는 기능입니다.
- 예를 들어 ransomware는 무수히 많이 있고, 변종도 존재합니다. 하지만 악성코드에서 사용되는 Icon으로 rule을 작성하여 Icon 유사도를 측정할 수 있습니다.
<img src="images/Hyara_4.png" width="100%">

- IDAViewWrapper를 사용하기 전에 만든 기능입니다. (old_version/Hyara_Using_simplecustviewer_Choose.py)
- Choose와 simplecustviewer를 이용하여 주소 클릭으로 Address를 지정해줍니다.
<img src="images/Hyara_old.png" width="100%">

- yara rule 작성에 도우미 역할을 해주는 간단한 플러그인입니다.
- rule 작성 시 와일드카드를 사용 할 때 어셈코드가 어떻게 변하는지 확인한 후에 작성해야합니다.
- 주로 변환해주는 웹 사이트를 사용했었는데, 도구를 사용하면 바로 확인이 가능합니다.
<img src="images/assem_disassembler.png" width="100%">