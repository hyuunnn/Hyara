from idaapi import PluginForm

from PyQt5.QtWidgets import QRadioButton, QTableWidget, QLineEdit, QPlainTextEdit, QPushButton, QLabel, QVBoxLayout, QGridLayout
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt

from capstone import *
from keystone import *


class Tools(PluginForm):

    def disassembler(self):
        CODE = bytearray.fromhex(self.Disassembler1.toPlainText().replace("\\x"," "))
        result = ""
        if self.RadioButton1.isChecked():
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            for i in md.disasm(CODE, 0x0):
                result += ("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)) + "\n"
            self.Disassembler2.clear()
            self.Disassembler2.insertPlainText(result)

        elif self.RadioButton2.isChecked():
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            for i in md.disasm(CODE, 0x0):
                result += ("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)) + "\n"
            self.Disassembler2.clear()
            self.Disassembler2.insertPlainText(result)

    def assembler(self):
        CODE = self.Assembler1.toPlainText()
        if self.RadioButton1.isChecked():
            try:
                ks = Ks(KS_ARCH_X86, KS_MODE_32)
                encoding, count = ks.asm(CODE)
                self.Assembler2.clear()
                result = []
                for i in encoding:
                    data = hex(i)[2:].upper()
                    if len(data) == 1:
                        result.append("0"+data)
                    else:
                        result.append(data)
                self.Assembler2.insertPlainText(' '.join(result))
            except KsError as e:
                print("ERROR: %s" %e)

        elif self.RadioButton2.isChecked():
            try:
                ks = Ks(KS_ARCH_X86, KS_MODE_64)
                encoding, count = ks.asm(CODE)
                self.Assembler2.clear()
                result = []
                for i in encoding:
                    data = hex(i)[2:].upper()
                    if len(data) == 1:
                        result.append("0"+data)
                    else:
                        result.append(data)
                self.Assembler2.insertPlainText(' '.join(result))
            except KsError as e:
                print("ERROR: %s" %e)

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.label1 = QLabel("Assembler")
        self.label2 = QLabel("Diassembler")
        self.label3 = QLabel("Answer")
        self.label4 = QLabel("Answer")
        self.Assembler1 = QPlainTextEdit()
        self.Assembler2 = QPlainTextEdit()
        self.Disassembler1 = QPlainTextEdit()
        self.Disassembler2 = QPlainTextEdit()
        self.EnterButton1 = QPushButton("Enter")
        self.EnterButton1.clicked.connect(self.assembler)
        self.EnterButton2 = QPushButton("Enter")
        self.EnterButton2.clicked.connect(self.disassembler)
        self.RadioButton1 = QRadioButton("x86")
        self.RadioButton2 = QRadioButton("x64")

        self.layout = QVBoxLayout()

        GL1 = QGridLayout()
        GL1.addWidget(self.label1, 0, 0)
        GL1.addWidget(self.label2, 0, 1)
        GL1.addWidget(self.Assembler1, 1, 0)
        GL1.addWidget(self.Disassembler1, 1, 1)
        GL1.addWidget(self.label3, 2, 0)
        GL1.addWidget(self.label4, 2, 1)
        GL1.addWidget(self.Assembler2, 3, 0)
        GL1.addWidget(self.Disassembler2, 3, 1)
        GL1.addWidget(self.RadioButton1, 4, 0)
        GL1.addWidget(self.RadioButton2, 4, 1)
        GL1.addWidget(self.EnterButton1, 5, 0)
        GL1.addWidget(self.EnterButton2, 5, 1)
        self.layout.addLayout(GL1)
        self.parent.setLayout(self.layout)  

    def OnClose(self, form):
        pass

class assem_Tool(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "assembler & disassembler"
    help = "help"
    wanted_name = "assembler & disassembler"
    wanted_hotkey = "Ctrl+Shift+A"

    def init(self):
        idaapi.msg("assembler_disassembler")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        plg = Tools()
        plg.Show("Assembler & Disassembler")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return assem_Tool()
