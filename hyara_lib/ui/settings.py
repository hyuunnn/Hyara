try:
    from PyQt5 import QtWidgets  # QtGui, QtCore
except:
    import PySide2.QtWidgets as QtWidgets

from abc import ABCMeta, abstractmethod
from ..plugins import yara_checker, yara_detector, yara_icon

import time
import sys

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
        self._start_address_button = QtWidgets.QPushButton("Select / Exit")
        self._end_address_button = QtWidgets.QPushButton("Select / Exit")

        self._check_comment = QtWidgets.QCheckBox()
        self._check_wildcard = QtWidgets.QCheckBox()
        self._check_string = QtWidgets.QCheckBox()
        self._check_rich_header = QtWidgets.QCheckBox()
        self._check_imphash = QtWidgets.QCheckBox()

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
        GL2.addWidget(self._start_address_button, 0, 2)
        GL2.addWidget(QtWidgets.QLabel("End Address : "), 0, 3)
        GL2.addWidget(self._end_address, 0, 4)
        GL2.addWidget(self._end_address_button, 0, 5)
        self.layout.addLayout(GL2)

        GL3 = QtWidgets.QGridLayout()
        GL3.addWidget(QtWidgets.QLabel("Comment Option"), 0, 0)
        GL3.addWidget(self._check_comment, 0, 1)
        GL3.addWidget(QtWidgets.QLabel("Wildcard Option"), 0, 2)
        GL3.addWidget(self._check_wildcard, 0, 3)
        GL3.addWidget(QtWidgets.QLabel("String Option"), 0, 4)
        GL3.addWidget(self._check_string, 0, 5)
        GL3.addWidget(QtWidgets.QLabel("Rich Header"), 0, 6)
        GL3.addWidget(self._check_rich_header, 0, 7)
        GL3.addWidget(QtWidgets.QLabel("Imphash"), 0, 8)
        GL3.addWidget(self._check_imphash, 0, 9)
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
    def get_disasm(self, start_address, end_address):
        pass

    @abstractmethod
    def get_hex(self, start_address, end_address):
        pass

    @abstractmethod
    def get_md5(self):
        pass

    def _make_hex_rule(self):
        self._result_plaintext.clear()
        self._result_plaintext.insertPlainText(
            "".join(self.get_hex(self._start_address.text(), self._end_address.text())).upper()
        )

    def _save_rule(self):
        self.rule_list[self._variable_name.text()] = {
            "text": self._result_plaintext.toPlainText(),
            "start": self._start_address.text(),
            "end": self._end_address.text(),
        }
        self._ui_populate_table()

    def _remove_rule(self):
        if self._remove_question() == QtWidgets.QMessageBox.Yes:
            self.rule_list.clear()
        self._ui_populate_table()

    def _yara_result(self) -> str:
        result = 'import "hash"\n'
        result += 'import "pe"\n\n'
        result += "rule {} \n".format(self._variable_name.text())
        result += "{\n"
        result += "  meta:\n"
        result += '      tool = "https://github.com/hy00un/Hyara"\n'
        result += '      version = "1.9"\n'
        result += '      date = "{}"\n'.format(time.strftime("%Y-%m-%d"))
        result += '      MD5 = "{}"\n'.format(self.get_md5())
        result += "  strings:\n"

        for name, value in self.rule_list.items():
            result += "      /*\n"
            for disasm, hex_value in zip(
                self.get_disasm(value["start"], value["end"]),
                self.get_hex(value["start"], value["end"]),
            ):
                mnemonic = disasm.split(" ")[0]
                operend = " ".join(disasm.split(" ")[1:]).strip()
                result += "          {:10}\t{:30}\t\t|{}\n".format(
                    mnemonic, operend, hex_value.upper()
                )

            result += "      */\n"
            result += "      $" + name + " = {" + "".join(value["text"]).upper() + "}\n"

        result += "  condition:\n"
        result += "      all of them"
        return result

    def _yara_export_rule(self):
        self._result_plaintext.clear()
        if len(self.rule_list) > 0:
            self._result_plaintext.insertPlainText(self._yara_result())

    def _yara_checker(self):
        # yara_checker.YaraChecker()
        pass

    def _yara_detector(self):
        # yara_detector.YaraDetector()
        pass

    def _yara_icon(self):
        # yara_icon.YaraIcon()
        pass

    def _ui_clicked_connect(self):
        # self._start_address_button.clicked.connect(partial(self.IDAWrapper, "1"))
        # self._end_address_button.clicked.connect(partial(self.IDAWrapper, "2"))
        self._make_button.clicked.connect(self._make_hex_rule)
        self._save_button.clicked.connect(self._save_rule)
        self._delete_button.clicked.connect(self._remove_rule)
        self._yara_export_button.clicked.connect(self._yara_export_rule)
        self._yara_checker_button.clicked.connect(self._yara_checker)
        self._yara_detector_button.clicked.connect(self._yara_detector)
        self._yara_icon_button.clicked.connect(self._yara_icon)