from idaapi import PluginForm
from PyQt5.QtWidgets import QCheckBox, QTableWidgetItem, QFileDialog, QTableWidget, QLineEdit, QPlainTextEdit, QPushButton, QLabel, QVBoxLayout, QGridLayout
from PyQt5.QtGui import QColor, QTextCharFormat, QFont, QSyntaxHighlighter, QPixmap, QIcon
from PyQt5.QtCore import QRegExp, Qt
from os.path import expanduser
from PIL.ImageQt import ImageQt
from PIL import Image

import os
import yara
import binascii
import time
import re
import pefile
import io

class YaraHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)

        quote_color = QTextCharFormat()
        color_ = QColor()
        color_.setRgb(255, 127, 80)
        quote_color.setForeground(color_)

        keyword_color = QTextCharFormat()
        color_ = QColor()
        color_.setRgb(135, 206, 235)
        keyword_color.setForeground(color_)

        hex_color = QTextCharFormat()
        color_ = QColor()
        color_.setRgb(0, 153, 0)
        hex_color.setForeground(color_)

        comment_color = QTextCharFormat()
        color_ = QColor()
        color_.setRgb(187, 93, 0)
        comment_color.setForeground(color_)

        keywords = [
            "\\ball\\b", "\\band\\b", "\\bany\\b", "\\bascii\\b", "\\bat\\b", "\\bcondition\\b", "\\bcontains\\b",
            "\\bentrypoint\\b", "\\bfalse\\b", "\\bfilesize\\b", "\\bfullword\\b", "\\bfor\\b", "\\bglobal\\b", "\\bin\\b",
            "\\bimport\\b", "\\binclude\\b", "\\bint8\\b", "\\bint16\\b", "\\bint32\\b", "\\bint8be\\b", "\\bint16be\\b",
            "\\bint32be\\b", "\\bmatches\\b", "\\bmeta\\b", "\\bnocase\\b", "\\bnot\\b", "\\bor\\b", "\\bof\\b",
            "\\bprivate\\b", "\\brule\\b", "\\bstrings\\b", "\\bthem\\b", "\\btrue\\b", "\\buint8\\b", "\\buint16\\b",
            "\\buint32\\b", "\\buint8be\\b", "\\buint16be\\b", "\\buint32be\\b", "\\bwide\\b"
        ]

        self.highlightingRules = [(QRegExp(keyword), keyword_color) # keyword
                for keyword in keywords]

        self.highlightingRules.append((QRegExp("\{[\S\s]*\}"), hex_color)) # hex string
        self.highlightingRules.append((QRegExp("\/.*\/"), quote_color)) # regex
        self.highlightingRules.append((QRegExp("\/\*[\S\s]*\*\/"), comment_color)) # comment
        self.highlightingRules.append((QRegExp("\/\/.*"), comment_color)) # comment
        self.highlightingRules.append((QRegExp("\".*\""), quote_color)) # double quote
        self.highlightingRules.append((QRegExp("\'.*\'"), quote_color)) # single quote

    def highlightBlock(self, text):
        for pattern, format in self.highlightingRules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)

            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)

        self.setCurrentBlockState(0)

class YaraIcon(PluginForm):
    def YaraMaker(self):
        for idx in range(len(self.img)):
            data_ = self.img[idx][int(self.LineEdit1.text(),16):int(self.LineEdit1.text(),16) + int(self.LineEdit2.text(),10)]
            self.LineEdit_list[idx].setText("{" + binascii.hexlify(data_) + "}")

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.pe = pefile.PE(GetInputFilePath())
        self.EntryPoint = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.ImageBase = self.pe.OPTIONAL_HEADER.ImageBase
        self.section_list = {}
        self.img = []
        self.img_label = []
        self.LineEdit_list = []
        self.PushButton_list = []
        self.label1 = QLabel("Start Offset : ")
        self.label2 = QLabel("Length : ")
        self.label3 = QLabel("Variable name : ")
        self.LineEdit1 = QLineEdit()
        self.LineEdit2 = QLineEdit()
        self.LineEdit3 = QLineEdit()
        self.PushButton1 = QPushButton("Enter")
        self.PushButton1.clicked.connect(self.YaraMaker) 

        for section in self.pe.sections:
            self.section_list[section.Name.decode("utf-8").replace("\x00","")] = [hex(section.VirtualAddress), hex(section.SizeOfRawData), hex(section.PointerToRawData)]

        for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            resource_type = entry.name
            if resource_type is None:
                resource_type = pefile.RESOURCE_TYPE.get(entry.struct.Id)

            for directory in entry.directory.entries:
                for resource in directory.directory.entries:
                    name = str(resource_type)
                    if name in "RT_ICON":
                        name = str(resource_type)
                        offset = resource.data.struct.OffsetToData
                        size = resource.data.struct.Size
                        RVA_ = int(self.section_list['.rsrc'][0],16) - int(self.section_list['.rsrc'][2],16)
                        real_offset = offset - RVA_
                        img_size = hex(size)[2:]
                        if len(img_size) % 2 == 1:
                            img_size = "0"+img_size

                        img_ = "\x00\x00\x01\x00\x01\x00\x30\x30\x00\x00\x01\x00\x08\x00" + bytearray.fromhex(img_size)[::-1] + "\x00\x00\x16\x00\x00\x00"
                        f = open(GetInputFilePath(),"rb")
                        f.seek(real_offset)
                        img_ += f.read(size)
                        f.close()
                        self.img.append(img_)
                        # print(hex(offset), real_offset)

        self.layout = QVBoxLayout()
        GL0 = QGridLayout()
        GL0.addWidget(self.label3, 0, 0)
        GL0.addWidget(self.LineEdit3, 0, 1)
        GL0.addWidget(self.label1, 0, 2)
        GL0.addWidget(self.LineEdit1, 0, 3)
        GL0.addWidget(self.label2, 0, 4)
        GL0.addWidget(self.LineEdit2, 0, 5)
        GL0.addWidget(self.PushButton1, 0, 6)
        self.layout.addLayout(GL0)

        GL1 = QGridLayout()
        for idx,i in enumerate(self.img):
            # https://stackoverflow.com/questions/35655755/qpixmap-argument-1-has-unexpected-type-pngimagefile?rq=1
            # https://stackoverflow.com/questions/32908639/open-pil-image-from-byte-file
            image2 = Image.open(io.BytesIO(i))
            qimage = ImageQt(image2)
            pixmap = QtGui.QPixmap.fromImage(qimage)

            self.img_label.append(QLabel())
            self.img_label[idx].setPixmap(pixmap)
            GL1.addWidget(self.img_label[idx], idx, 0)

            self.LineEdit_list.append(QLineEdit())
            GL1.addWidget(self.LineEdit_list[idx], idx, 1)

            self.PushButton_list.append(QPushButton("Save Icon rule"))
            GL1.addWidget(self.PushButton_list[idx], idx, 2)

        self.layout.addLayout(GL1)
        self.parent.setLayout(self.layout)

    def OnClose(self, form):
        pass

class YaraChecker(PluginForm):
    def choose_path(self):
        path = QFileDialog.getExistingDirectory(
            self.parent,
            "Open a folder",
            expanduser("~"),
            QFileDialog.ShowDirsOnly)
        self.path.setText(path)

    def Search(self):
        rule = yara.compile(source=self.TextEdit1.toPlainText())
        result = {}
        for i in os.walk(self.path.text()):
            for j in i[2]:
                try:
                    f = open(i[0] + "\\" + j, "rb")
                    data = f.read()
                    matches = rule.match(data=data)
                    f.close()
                    for match in matches:
                        strings = match.strings[0]
                        result[os.path.basename(j)] = [i[0], hex(strings[0]).replace("L",""), strings[1], binascii.hexlify(strings[2])]
                except IOError: # Permission denied
                    continue
        self.tableWidget.setRowCount(len(result.keys()))
        self.label4.setText(str(len(result.keys())))
        
        for idx, filename in enumerate(result.keys()):
            self.tableWidget.setItem(idx, 0, QTableWidgetItem(result[filename][0]))
            self.tableWidget.setItem(idx, 1, QTableWidgetItem(filename))
            self.tableWidget.setItem(idx, 2, QTableWidgetItem(result[filename][1]))
            self.tableWidget.setItem(idx, 3, QTableWidgetItem(result[filename][2]))
            self.tableWidget.setItem(idx, 4, QTableWidgetItem(result[filename][3]))
        self.layout.addWidget(self.tableWidget)

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.label1 = QLabel("Search Path")
        self.path = QLineEdit()
        self.PathButton = QPushButton("path")
        self.PathButton.clicked.connect(self.choose_path)        
        self.label2 = QLabel("Yara rule")
        self.TextEdit1 = QPlainTextEdit()
        self.TextEdit1.setStyleSheet("""QPlainTextEdit{
                                            font-family:'Consolas';}""")
        self.highlighter = YaraHighlighter(self.TextEdit1.document())
        self.TextEdit1.insertPlainText(self.data)
        self.SearchButton = QPushButton("Search")
        self.SearchButton.clicked.connect(self.Search)
        self.label3 = QLabel("Detect Count : ")
        self.label4 = QLabel("0")

        self.layout = QVBoxLayout()
        GL1 = QGridLayout()
        GL1.addWidget(self.path, 0, 0)
        GL1.addWidget(self.PathButton, 0, 1)
        GL1.addWidget(self.label3, 0, 2)
        GL1.addWidget(self.label4, 0, 3)
        self.layout.addLayout(GL1)

        self.layout.addWidget(self.label2)
        self.layout.addWidget(self.TextEdit1)
        self.layout.addWidget(self.SearchButton)

        self.tableWidget = QTableWidget()
        self.tableWidget.setRowCount(0)
        self.tableWidget.setColumnCount(5)
        self.tableWidget.setHorizontalHeaderLabels(["Path", "Filename", "Address", "Variable_name", "String"])
        self.layout.addWidget(self.tableWidget)
        self.parent.setLayout(self.layout)

    def OnClose(self, form):
        pass


class YaraGenerator(PluginForm):
    def YaraExport(self):
        info = idaapi.get_inf_structure()
        if info.is_64bit():
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        elif info.is_32bit():
            md = Cs(CS_ARCH_X86, CS_MODE_32)

        result = ""
        result += "rule " + self.Variable_name.text() + "\n{\n"
        result += "  meta:\n"
        result += "      tool = \"https://github.com/hy00un/ida_python_scripts/blob/master/YaraGenerator.py\"\n"
        result += "      date = \"" + time.strftime("%Y-%m-%d") + "\"\n"
        result += "      MD5 = \"" + GetInputFileMD5() + "\"\n"
        result += "  strings:\n"
        for name in self.ruleset_list.keys():
            CODE = bytearray.fromhex(self.ruleset_list[name][0][1:-1].strip().replace("\\x"," "))
            if self.CheckBox1.isChecked():
                result += "      /*\n"
                for i in md.disasm(CODE, 0x1000):
                    byte_data = "".join('{:02x}'.format(x) for x in i.bytes)
                    result += "          %-10s\t%-30s\t\t|%s" % (i.mnemonic.upper(), i.op_str.upper().replace("0X","0x"), byte_data.upper()) + "\n"
                result += "      */\n"

            # http://sparksandflames.com/files/x86InstructionChart.html
            # https://pnx.tf/files/x86_opcode_structure_and_instruction_overview.png
            # http://ref.x86asm.net/coder32.html
            if self.CheckBox2.isChecked(): # yara wildcard isChecked()
                opcode = []
                CODE = bytearray.fromhex(self.ruleset_list[name][0][1:-1].strip().replace("\\x"," "))
                for i in md.disasm(CODE, 0x1000):
                    byte_data = "".join('{:02x}'.format(x) for x in i.bytes)

                    if byte_data.startswith("ff"): # ex) ff d7 -> call edi, 8b 3d a8 e1 40 00 -> mov edi, ds:GetDlgItem
                        opcode.append("ff[1-5]")

                    elif byte_data.startswith("0f"): # ex) 0f 84 bb 00 00 00 -> jz loc_40112A, 0f b6 0b -> movzx cx, byte ptr [ebx]
                        opcode.append("0f[1-5]") # (multi byte)

                    elif re.compile("7[0-9a-f]").match(byte_data): # jo, jno, jb, jnb, jz, jnz, jbe, ja, js, jns, jp, jnp, jl, jnl, jle, jnle
                        opcode.append(byte_data[2:]+"??") # ex) 7c 7f -> jl 0x81 (7c only 1 byte) (1byte < have 0f)

                    elif i.mnemonic == "push":
                        if re.compile("5[0-7]|0(6|e)|1(6|e)").match(byte_data): # push e[a-b-c]x ..
                            opcode.append(byte_data[:1]+"?")
                        elif re.compile("6(8|a)+").match(byte_data):
                            opcode.append(byte_data)

                    elif i.mnemonic == "pop":
                        if re.compile("5[8-f]|07|1(7|f)").match(byte_data): # pop e[a-b-c]x ..
                            opcode.append(byte_data[:1]+"?")
                        elif re.compile("8f").match(byte_data):
                            opcode.append(byte_data)

                    elif i.mnemonic == "mov":
                        if re.compile("b[8-f]").match(byte_data): # ex) b8 01 22 00 00 -> mov eax, 0x2201, bf 38 00 00 00 -> mov edi, 38 , 8b 54 24 10 -> mov edx, [esp+32ch+var_31c]
                            opcode.append(byte_data[:2]+"[4]")
                        elif re.compile("b[0-7]").match(byte_data): # ex) b7 60 -> mov bh, 0x60
                            opcode.append("b?"+byte_data[2:])
                        elif re.compile("8[8-9a-c]|8e|c[6-7]").match(byte_data):
                            opcode.append(byte_data[:2]+"[1-8]") # ex) 8b 5c 24 14 -> mob ebx, [esp+10+ThreadParameter], 8b f0 -> mov esi, eax , c7 44 24 1c 00 00 00 00 -> mov [esp+338+var_31c], 0
                        elif re.compile("a[0-3]").match(byte_data):
                            opcode.append(byte_data[:2]+"[1-4]") # ex) a1 60 40 41 00 -> mov eax, __security_cookie

                    elif i.mnemonic == "inc":
                        if re.compile("4[0-7]").match(byte_data):
                            opcode.append(byte_data[:1]+"?")

                    elif i.mnemonic == "dec":
                        if re.compile("4[8-9a-f]").match(byte_data): # 48 ~ 4f
                            opcode.append(byte_data[:1]+"?")

                    elif i.mnemonic == "xor":
                        if re.compile("3[0-3]").match(byte_data):
                            opcode.append(byte_data[:2]+"[1-4]")
                        elif re.compile("34").match(byte_data): # ex) 34 da -> xor al, 0xda 
                            opcode.append(byte_data[:2]+"??")
                        elif re.compile("35").match(byte_data): # ex) 35 da 00 00 00 -> xor eax, 0xda
                            opcode.append("35[4]")

                    elif i.mnemonic == "add":
                        if re.compile("0[0-3]").match(byte_data):
                            opcode.append(byte_data[:2]+"[1-4]")
                        elif re.compile("04").match(byte_data): # ex) 04 da -> xor al, 0xda 
                            opcode.append(byte_data[:2]+"??")
                        elif re.compile("05").match(byte_data): # ex) 05 da 00 00 00 -> xor eax, 0xda
                            opcode.append("05[4]")

                    elif i.mnemonic == "call":
                        if re.compile("e8").match(byte_data):
                            opcode.append("e8[1-8]") # call address(?? ?? ?? ??)

                    elif i.mnemonic == "test":
                        if re.compile("8[4-5]|a8").match(byte_data): # ex) 84 ea -> test dl, ch
                            opcode.append(byte_data[:2]+"??") 
                        elif re.compile("a9").match(byte_data): # ex) a9 ea 00 00 00 -> test eax, 0xea
                            opcode.append("a9[4]")

                    elif i.mnemonic == "and":
                        if re.compile("8[0-3]").match(byte_data):
                            opcode.append(byte_data[:3]+"?[1-8]") # ex) 81 e3 f8 07 00 00 -> and ebx, 7f8
                        elif re.compile("2[0-3]").match(byte_data):
                            opcode.append(byte_data[:2]+"[1-4]")
                        elif re.compile("24").match(byte_data):
                            opcode.append(byte_data[:2]+"??") # ex) 22 d1 -> and dl, cl
                        elif re.compile("25").match(byte_data):
                            opcode.append(byte_data[:2]+"[4]")

                    elif i.mnemonic == "lea":
                        if re.compile("8d").match(byte_data): # ex) 8d 9b 00 00 00 00 -> lea ebx, [ebx+0] == 8d 1b
                            opcode.append("8d[1-6]")

                    elif i.mnemonic == "sub":
                        if re.compile("2[8a-b]").match(byte_data): # ex) 2a 5c 24 14 -> sub	bl, byte ptr [esp + 0x14]
                            opcode.append(byte_data[:2]+"[1-4]")
                        if re.compile("2c").match(byte_data): # ex) 28 da -> sub dl, bl
                            opcode.append(byte_data[:2]+"??")
                        elif re.compile("2d").match(byte_data): # ex) 2d da 00 00 00 -> sub eax, 0xda
                            opcode.append("2d[4]")
                        elif re.compile("8[2-3]").match(byte_data):
                            opcode.append("8?"+byte_data[2:])

                    elif i.mnemonic == "or":
                        if re.compile("0[8a-b]").match(byte_data): # ex) 08 14 30 -> or byte ptr [eax + esi], dl , 0b 5c 24 14 -> or ebx, dword ptr [esp + 0x14]
                            opcode.append(byte_data[:2]+"[1-4]")
                        elif re.compile("0c").match(byte_data): # ex) 0c ea -> or al, 0xea
                            opcode.append(byte_data[:2]+"??")
                        elif re.compile("0d").match(byte_data): # ex) 0d ea 00 00 00 -> or eax, 0xea
                            opcode.append("0d[4]")

                    elif i.mnemonic == "cmp":
                        if re.compile("3[8a-b]").match(byte_data):
                            opcode.append(byte_data[:2]+"[1-4]")
                        elif re.compile("3c").match(byte_data): # ex) 3a ea -> cmp ch, dl
                            opcode.append(byte_data[:2]+"??")
                        elif re.compile("3d").match(byte_data): # ex) 3d ea 00 00 00 -> cmp eax, 0xea
                            opcode.append("3d[4]")

                    elif i.mnemonic == "shl" or i.mnemonic == "sar":
                        if re.compile("c[0-1]").match(byte_data): # ex) c1 fa 02 -> sar edx, 2 , 
                            opcode.append(byte_data[:2]+"[2]")
                        elif re.compile("d[0-3]").match(byte_data): # ex) d0 fa -> sar dl, 1
                            opcode.append(byte_data[:2]+"??")
                    else:
                        opcode.append(byte_data)

                try:
                    if ''.join(opcode)[-1] == "]": # syntax error, unexpected '}', expecting _BYTE_ or _MASKED_BYTE_ or '(' or '['
                        opcode.append("??")
                except:
                    pass

                result += "      $" + name + " = {" + ''.join(opcode) + "}\n"
            else:
                result += "      $" + name + " = " + self.ruleset_list[name][0]+"\n"
        result += "  condition:\n"
        result += "      all of them\n"
        result += "}"
        self.TextEdit1.clear()
        self.TextEdit1.insertPlainText(result)

    def DeleteRule(self):
        if idaapi.ask_yn(idaapi.ASKBTN_NO, "Delete Yara Rule"):
            self.ruleset_list = {}
        self.tableWidget.setRowCount(len(self.ruleset_list.keys()))
        self.tableWidget.setColumnCount(4)
        self.tableWidget.setHorizontalHeaderLabels(["Variable_name", "Rule", "Start", "End"])
        for idx, name in enumerate(self.ruleset_list.keys()):
            self.tableWidget.setItem(idx, 0, QTableWidgetItem(name))
            self.tableWidget.setItem(idx, 1, QTableWidgetItem(self.ruleset_list[name][0]))
            self.tableWidget.setItem(idx, 2, QTableWidgetItem(self.ruleset_list[name][1]))
            self.tableWidget.setItem(idx, 3, QTableWidgetItem(self.ruleset_list[name][2]))
        self.layout.addWidget(self.tableWidget)

    def MakeRule(self):
        ByteCode = []
        start = int(self.StartAddress.text(), 16)
        end = int(self.EndAddress.text(), 16)

        while start <= end:
            sub_end = NextHead(start)
            data = binascii.hexlify(GetManyBytes(start, sub_end-start))
            ByteCode.append(data)
            start = sub_end

        self.TextEdit1.clear()
        self.TextEdit1.insertPlainText("{" + ''.join(ByteCode) + "}")

    def SaveRule(self):
        #info = idaapi.get_inf_structure()
        #if info.is_64bit():
        #    md = Cs(CS_ARCH_X86, CS_MODE_64)
        #elif info.is_32bit():
        #    md = Cs(CS_ARCH_X86, CS_MODE_32)
        #CODE = bytearray.fromhex(self.TextEdit1.toPlainText()[1:-1].strip().replace("\\x"," "))
        #for i in md.disasm(CODE, 0x1000):
        #    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

        self.ruleset_list[self.Variable_name.text()] = [self.TextEdit1.toPlainText(), self.StartAddress.text(), self.EndAddress.text()]
        self.tableWidget.setRowCount(len(self.ruleset_list.keys()))
        self.tableWidget.setColumnCount(4)
        self.tableWidget.setHorizontalHeaderLabels(["Variable_name", "Rule", "Start", "End"])
        for idx, name in enumerate(self.ruleset_list.keys()):
            self.tableWidget.setItem(idx, 0, QTableWidgetItem(name))
            self.tableWidget.setItem(idx, 1, QTableWidgetItem(self.ruleset_list[name][0]))
            self.tableWidget.setItem(idx, 2, QTableWidgetItem(self.ruleset_list[name][1]))
            self.tableWidget.setItem(idx, 3, QTableWidgetItem(self.ruleset_list[name][2]))
        self.layout.addWidget(self.tableWidget)

    def YaraChecker(self):
        self.YaraChecker = YaraChecker()
        self.YaraChecker.data = self.TextEdit1.toPlainText()
        self.YaraChecker.Show("YaraChecker")

    def YaraIcon(self):
        self.YaraIcon = YaraIcon()
        self.YaraIcon.Show("YaraIcon")

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.ruleset_list = {}
        self.label1 = QLabel("Variable name : ")
        self.label_1 = QLabel("comment option")
        self.CheckBox1 = QCheckBox()
        self.label_2 = QLabel("wildcard option")
        self.CheckBox2 = QCheckBox()
        self.Variable_name = QLineEdit()
        self.label2 = QLabel("Start Address : ")
        self.StartAddress = QLineEdit()
        self.label3 = QLabel("End Address : ")
        self.EndAddress = QLineEdit()
        self.TextEdit1 = QPlainTextEdit()

        self.MakeButton = QPushButton("Make")
        self.MakeButton.clicked.connect(self.MakeRule)
        self.SaveButton = QPushButton("Save")
        self.SaveButton.clicked.connect(self.SaveRule)
        self.DeleteButton = QPushButton("Delete")
        self.DeleteButton.clicked.connect(self.DeleteRule)
        self.YaraExportButton = QPushButton("Export Yara Rule")
        self.YaraExportButton.clicked.connect(self.YaraExport)
        self.YaraCheckerButton = QPushButton("Yara Checker")
        self.YaraCheckerButton.clicked.connect(self.YaraChecker)
        self.YaraIconButton = QPushButton("Yara Icon")
        self.YaraIconButton.clicked.connect(self.YaraIcon)

        self.layout = QVBoxLayout()

        GL1 = QGridLayout()
        GL1.addWidget(self.label1, 0, 0)
        GL1.addWidget(self.Variable_name, 0, 1)
        GL1.addWidget(self.label_1 , 0, 2)
        GL1.addWidget(self.CheckBox1, 0, 3)
        GL1.addWidget(self.label_2 , 0, 4)
        GL1.addWidget(self.CheckBox2, 0, 5)
        self.layout.addLayout(GL1)

        GL2 = QGridLayout()
        GL2.addWidget(self.label2, 0, 1)
        GL2.addWidget(self.StartAddress, 0, 2)
        GL2.addWidget(self.label3, 0, 3)
        GL2.addWidget(self.EndAddress, 0, 4)
        self.layout.addLayout(GL2)

        self.layout.addWidget(self.TextEdit1)

        GL3 = QGridLayout()
        GL3.addWidget(self.MakeButton, 0, 0)
        GL3.addWidget(self.SaveButton, 0, 1)
        GL3.addWidget(self.DeleteButton, 0, 2)
        GL3.addWidget(self.YaraExportButton, 0, 3)
        GL3.addWidget(self.YaraCheckerButton, 0, 4)
        GL3.addWidget(self.YaraIconButton, 0, 5)
        self.layout.addLayout(GL3)

        self.tableWidget = QTableWidget()
        self.tableWidget.setRowCount(0)
        self.tableWidget.setColumnCount(4)
        self.tableWidget.setHorizontalHeaderLabels(["Variable_name", "Rule", "Start", "End"])
        self.layout.addWidget(self.tableWidget)

        self.parent.setLayout(self.layout)

    def OnClose(self, form):
        pass

class YaraPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is YaraGenerator"
    help = "help"
    wanted_name = "Yara_Generator"
    wanted_hotkey = "Ctrl+Shift+Y"

    def init(self):
        idaapi.msg("YaraGenerator\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        plg = YaraGenerator()
        plg.Show("YaraGenerator")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return YaraPlugin()
