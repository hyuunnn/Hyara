from sys import modules

if "idaapi" in modules:
    # We are running inside IDA
    from PyQt5 import QtWidgets
else:
    # We are running inside Cutter or Binary Ninja
    import PySide2.QtWidgets as QtWidgets

from abc import ABCMeta, abstractmethod
from ..plugins import yara_checker, yara_detector, yara_icon

import time
import pefile

# Based GUI
class MainGUI:
    def __init__(self):
        self.layout = QtWidgets.QVBoxLayout()
        self.rule_list = {}
        self._ui_init()

    def _ui_init(self):
        self._ui_setting()
        self._ui_init_layout()
        self._ui_init_table()

    def _ui_setting(self):
        self._variable_name = QtWidgets.QLineEdit()

        self._start_address = QtWidgets.QLineEdit()
        self._end_address = QtWidgets.QLineEdit()

        self._check_comment = QtWidgets.QCheckBox()
        self._check_wildcard = QtWidgets.QCheckBox()
        self._check_string = QtWidgets.QCheckBox()
        self._check_rich_header = QtWidgets.QCheckBox()
        self._check_imphash = QtWidgets.QCheckBox()
        self._check_pdb_path = QtWidgets.QCheckBox()

        self._result_plaintext = QtWidgets.QPlainTextEdit()

        self._make_button = QtWidgets.QPushButton("Make")
        self._save_button = QtWidgets.QPushButton("Save")
        self._delete_button = QtWidgets.QPushButton("Delete")
        self._yara_export_button = QtWidgets.QPushButton("Export Yara Rule")
        self._yara_checker_button = QtWidgets.QPushButton("Yara Checker")
        self._yara_detector_button = QtWidgets.QPushButton("Yara Detector")
        self._yara_icon_button = QtWidgets.QPushButton("Yara Icon")

    def _ui_init_layout(self):
        GL1 = QtWidgets.QGridLayout()
        GL1.addWidget(QtWidgets.QLabel("Variable Name : "), 0, 0)
        GL1.addWidget(self._variable_name, 0, 1)
        self.layout.addLayout(GL1)

        GL2 = QtWidgets.QGridLayout()
        GL2.addWidget(QtWidgets.QLabel("Start Address : "), 0, 0)
        GL2.addWidget(self._start_address, 0, 1)
        GL2.addWidget(QtWidgets.QLabel("End Address : "), 0, 3)
        GL2.addWidget(self._end_address, 0, 4)
        self.layout.addLayout(GL2)

        GL3 = QtWidgets.QHBoxLayout()
        GL3.addWidget(self._check_comment)
        GL3.addWidget(QtWidgets.QLabel("Comment Option"))
        GL3.addStretch()

        GL3.addWidget(self._check_wildcard)
        GL3.addWidget(QtWidgets.QLabel("Wildcard Option"))
        GL3.addStretch()

        GL3.addWidget(self._check_string)
        GL3.addWidget(QtWidgets.QLabel("String Option"))
        GL3.addStretch()

        GL3.addWidget(self._check_rich_header)
        GL3.addWidget(QtWidgets.QLabel("Rich Header"))
        GL3.addStretch()

        GL3.addWidget(self._check_imphash)
        GL3.addWidget(QtWidgets.QLabel("Imphash"))
        GL3.addStretch()

        GL3.addWidget(self._check_pdb_path)
        GL3.addWidget(QtWidgets.QLabel("PDB Path"))
        self.layout.addLayout(GL3)

        self.layout.addWidget(self._result_plaintext)

        GL4 = QtWidgets.QGridLayout()
        GL4.addWidget(self._make_button, 0, 0)
        GL4.addWidget(self._save_button, 0, 1)
        GL4.addWidget(self._delete_button, 0, 2)
        GL4.addWidget(self._yara_export_button, 0, 3)
        GL4.addWidget(self._yara_checker_button, 0, 4)
        GL4.addWidget(self._yara_detector_button, 0, 5)
        GL4.addWidget(self._yara_icon_button, 0, 6)
        self.layout.addLayout(GL4)

    def _ui_init_table(self):
        self._table = QtWidgets.QTableWidget()
        self._table.cellDoubleClicked.connect(self._ui_table_click)
        self._table.setRowCount(0)
        self._table.setColumnCount(4)
        self._table.setHorizontalHeaderLabels(["Variable Name", "Rule", "Start", "End"])
        self.layout.addWidget(self._table)

    def _ui_populate_table(self):
        self._table.setRowCount(len(self.rule_list))
        for idx, (name, value) in enumerate(self.rule_list.items()):
            self._table.setItem(idx, 0, QtWidgets.QTableWidgetItem(name))
            self._table.setItem(idx, 1, QtWidgets.QTableWidgetItem(value["text"]))
            self._table.setItem(idx, 2, QtWidgets.QTableWidgetItem(value["start"]))
            self._table.setItem(idx, 3, QtWidgets.QTableWidgetItem(value["end"]))
        self.layout.addWidget(self._table)

    def _ui_table_click(self, row, column):
        if self._remove_question() == QtWidgets.QMessageBox.Yes:
            variable_name = self._table.item(row, 0).text()
            del self.rule_list[variable_name]
        self._ui_populate_table()

    def _remove_question(self):
        msg = QtWidgets.QMessageBox.question(
            None,
            "Message",
            "Remove Yara Rule",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        )
        return msg


# add feature
class HyaraGUI(MainGUI):
    __metaclass__ = ABCMeta

    def __init__(self):
        super(HyaraGUI, self).__init__()
        self._ui_clicked_connect()

    @abstractmethod
    def get_disasm(self, start_address, end_address) -> list:
        pass

    @abstractmethod
    def get_hex(self, start_address, end_address) -> list:
        pass

    @abstractmethod
    def get_comment_hex(self, start_address, end_address) -> list:
        pass

    @abstractmethod
    def get_string(self, start_address, end_address) -> list:
        pass

    @abstractmethod
    def get_filepath(self) -> str:
        pass

    @abstractmethod
    def get_md5(self) -> str:
        pass

    @abstractmethod
    def get_imphash(self) -> str:
        pass

    @abstractmethod
    def get_rich_header(self) -> str:
        pass

    @abstractmethod
    def get_pdb_path(self) -> str:
        pass

    @abstractmethod
    def jump_to(self, addr):
        pass

    def pretty_hex(self, data):
        return " ".join(data[i : i + 2] for i in range(0, len(data), 2)).upper()

    def get_comment(self, value):
        if value["type"] == "hex":
            self.result += "      /*\n"
            for disasm, hex_value in zip(
                self.get_disasm(int(value["start"], 16), int(value["end"], 16)),
                self.get_comment_hex(int(value["start"], 16), int(value["end"], 16)),
            ):
                mnemonic = disasm.split(" ")[0]
                operend = " ".join(disasm.split(" ")[1:]).strip()
                self.result += "          {:10}\t{:30}\t\t|{}\n".format(
                    mnemonic, operend, hex_value.upper()
                )

            self.result += "      */\n"

    def get_rule_data(self, name, value):
        if value["type"] == "string":
            self.result += "      $" + name + ' = "' + value["text"] + '" nocase wide ascii\n'
        else:
            self.result += "      $" + name + " = {" + self.pretty_hex(value["text"]) + "}\n"

    def _make_hex_rule(self):
        self._result_plaintext.clear()
        if self._check_string.isChecked():
            self._result_plaintext.insertPlainText(
                "\n".join(
                    self.get_string(
                        int(self._start_address.text(), 16), int(self._end_address.text(), 16)
                    )
                )
            )
        else:
            self._result_plaintext.insertPlainText(
                "".join(
                    self.get_hex(
                        int(self._start_address.text(), 16), int(self._end_address.text(), 16)
                    )
                ).upper()
            )

    def _save_rule(self):
        if self._check_string.isChecked():
            string_list = self._result_plaintext.toPlainText().split("\n")
            for idx, string in enumerate(string_list):
                self.rule_list["{}_{}".format(self._variable_name.text(), str(idx))] = {
                    "text": string,
                    "start": self._start_address.text(),
                    "end": self._end_address.text(),
                    "type": "string",
                }
        else:
            self.rule_list[self._variable_name.text()] = {
                "text": self._result_plaintext.toPlainText(),
                "start": self._start_address.text(),
                "end": self._end_address.text(),
                "type": "hex",
            }
        self._ui_populate_table()

    def _remove_rule(self):
        if self._remove_question() == QtWidgets.QMessageBox.Yes:
            self.rule_list.clear()
        self._ui_populate_table()

    def _yara_result(self) -> str:
        self.result = 'import "hash"\n'
        self.result += 'import "pe"\n\n'
        self.result += "rule {} \n".format(self._variable_name.text())
        self.result += "{\n"
        self.result += "  meta:\n"
        self.result += '      tool = "https://github.com/hy00un/Hyara"\n'
        self.result += '      version = "2.0"\n'
        self.result += '      date = "{}"\n'.format(time.strftime("%Y-%m-%d"))
        self.result += '      MD5 = "{}"\n'.format(self.get_md5())
        self.result += "  strings:\n"

        for name, value in self.rule_list.items():

            if self._check_comment.isChecked():
                self.get_comment(value)

            self.get_rule_data(name, value)

        self.result += "  condition:\n"
        self.result += "      all of them"

        try:
            # Check if opened file is a PE
            pefile.PE(self.get_filepath())
            if self._check_rich_header.isChecked():
                self.result += (
                    ' and hash.md5(pe.rich_signature.clear_data) == "'
                    + self.get_rich_header()
                    + '"'
                )

            if self._check_imphash.isChecked():
                self.result += ' and pe.imphash() == "' + self.get_imphash() + '"'

            if self._check_pdb_path.isChecked():
                self.result += ' and pe.pdb_path == "' + self.get_pdb_path() + '"'
        except pefile.PEFormatError:
            # Not a PE file, continue
            pass

        self.result += "\n}"
        return self.result

    def _yara_export_rule(self):
        self._result_plaintext.clear()
        if len(self.rule_list) > 0:
            self._result_plaintext.insertPlainText(self._yara_result())

    def _yara_checker(self):
        yara_checker.YaraChecker(self._result_plaintext.toPlainText())._ui_init()

    def _yara_detector(self):
        yara_detector.YaraDetector(
            self._result_plaintext.toPlainText(), self.get_filepath(), self.jump_to
        )._ui_init()

    def _yara_icon(self):
        yara_icon.YaraIcon(self.get_filepath(), self.rule_list, self._ui_populate_table)._ui_init()

    def _ui_clicked_connect(self):
        self._make_button.clicked.connect(self._make_hex_rule)
        self._save_button.clicked.connect(self._save_rule)
        self._delete_button.clicked.connect(self._remove_rule)
        self._yara_export_button.clicked.connect(self._yara_export_rule)
        self._yara_checker_button.clicked.connect(self._yara_checker)
        self._yara_detector_button.clicked.connect(self._yara_detector)
        self._yara_icon_button.clicked.connect(self._yara_icon)