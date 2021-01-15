try:
    from PyQt5 import QtWidgets
except:
    import PySide2.QtWidgets as QtWidgets

import os.path
import yara
import pefile


class YaraDetector(QtWidgets.QDialog):
    def __init__(self, rule_text, file_path, jump_to):
        super(YaraDetector, self).__init__()
        self.setObjectName("YaraDetector")
        self.setWindowTitle("YaraDetector")
        self.rule_text = rule_text
        self.file_path = file_path
        self.jump_to = jump_to

    def _ui_init(self):
        self._ui_setting()
        self._ui_init_layout()
        self._ui_clicked_connect()
        self._ui_init_table()
        self.exec_()

    def _ui_setting(self):
        self._folder_path = QtWidgets.QLineEdit()
        self._path_button = QtWidgets.QPushButton("File")
        self._hyara_checkbox = QtWidgets.QCheckBox()
        self._search_button = QtWidgets.QPushButton("Search")

    def _ui_init_layout(self):
        self.layout = QtWidgets.QVBoxLayout()
        GL1 = QtWidgets.QGridLayout()
        GL1.addWidget(QtWidgets.QLabel("Yara Path : "), 0, 0)
        GL1.addWidget(self._folder_path, 0, 1)
        GL1.addWidget(self._path_button, 0, 2)
        GL1.addWidget(QtWidgets.QLabel("Hyara Rule"), 0, 3)
        GL1.addWidget(self._hyara_checkbox, 0, 4)
        self.layout.addLayout(GL1)

        self.layout.addWidget(self._search_button)
        self.setLayout(self.layout)

    def _ui_clicked_connect(self):
        self._search_button.clicked.connect(self._search)
        self._path_button.clicked.connect(self._select_path)

    def _ui_init_table(self):
        self._table = QtWidgets.QTableWidget()
        self._table.cellClicked.connect(self.jump_addr)
        self._table.setRowCount(0)
        self._table.setColumnCount(4)
        self._table.setHorizontalHeaderLabels(["Address", "Rule Name", "Variable Name", "Value"])
        self.layout.addWidget(self._table)

    def get_binarydata(self):
        with open(self.file_path, "rb") as f:
            return f.read()

    def get_va_from_offset(self, addr):
        pe = pefile.PE(self.file_path)
        return pe.OPTIONAL_HEADER.ImageBase + pe.get_rva_from_offset(addr)

    def jump_addr(self, row, column):
        addr = int(self._table.item(row, 0).text(), 16)  # RAW
        self.jump_to(self.get_va_from_offset(addr))

    def _search(self):
        result = []
        data = self.get_binarydata()

        if self._hyara_checkbox.isChecked():
            self.rule = yara.compile(source=self.rule_text)
        else:
            with open(self._folder_path.text(), "r") as f:
                self.rule = yara.compile(source=f.read())

        matches = self.rule.match(data=data)
        for match in matches:
            for i in match.strings:
                result.append(
                    {
                        "addr": hex(i[0]),
                        "rule_name": match.rule,
                        "variable_name": i[1],
                        "value": i[2].hex(),
                    }
                )
        self._table.setRowCount(len(result))

        for idx, value in enumerate(result):
            self._table.setItem(idx, 0, QtWidgets.QTableWidgetItem(value["addr"]))
            self._table.setItem(idx, 1, QtWidgets.QTableWidgetItem(value["rule_name"]))
            self._table.setItem(idx, 2, QtWidgets.QTableWidgetItem(value["variable_name"]))
            self._table.setItem(idx, 3, QtWidgets.QTableWidgetItem(value["value"]))
        self.layout.addWidget(self._table)

    def _select_path(self):
        path = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Open a file",
            os.path.expanduser("~"),
            "Yara Rule Files (*.yar *.yara);;All Files (*)",
        )

        if path:
            self._folder_path.setText(path[0])