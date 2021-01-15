try:
    from PyQt5 import QtWidgets
except:
    import PySide2.QtWidgets as QtWidgets

import os.path
import yara


class YaraChecker(QtWidgets.QDialog):
    def __init__(self, rule_text):
        super(YaraChecker, self).__init__()
        self.setObjectName("YaraChecker")
        self.setWindowTitle("YaraChecker")
        self.rule_text = rule_text

    def _ui_init(self):
        self._ui_setting()
        self._ui_init_layout()
        self._ui_clicked_connect()
        self._ui_init_table()
        self.exec_()

    def _ui_setting(self):
        self._folder_path = QtWidgets.QLineEdit()
        self._path_button = QtWidgets.QPushButton("Path")
        self._rule_plaintext = QtWidgets.QPlainTextEdit()
        self._rule_plaintext.setStyleSheet("QPlainTextEdit{font-family:'Consolas';}")
        self._rule_plaintext.insertPlainText(self.rule_text)
        self._search_button = QtWidgets.QPushButton("Search")
        self._detect_count = QtWidgets.QLabel("0")

    def _ui_init_layout(self):
        self.layout = QtWidgets.QVBoxLayout()
        GL1 = QtWidgets.QGridLayout()
        GL1.addWidget(QtWidgets.QLabel("Folder Path : "), 0, 0)
        GL1.addWidget(self._folder_path, 0, 1)
        GL1.addWidget(self._path_button, 0, 2)
        GL1.addWidget(QtWidgets.QLabel("Detect Count : "), 0, 3)
        GL1.addWidget(self._detect_count, 0, 4)
        self.layout.addLayout(GL1)

        self.layout.addWidget(QtWidgets.QLabel("Yara rule"))
        self.layout.addWidget(self._rule_plaintext)
        self.layout.addWidget(self._search_button)
        self.setLayout(self.layout)

    def _ui_clicked_connect(self):
        self._search_button.clicked.connect(self._search)
        self._path_button.clicked.connect(self._select_path)

    def _ui_init_table(self):
        self._table = QtWidgets.QTableWidget()
        self._table.setRowCount(0)
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels(
            ["Path", "Filename", "Address", "Variable Name", "String"]
        )
        self.layout.addWidget(self._table)

    def _search(self):
        result = {}
        rule = yara.compile(source=self._rule_plaintext.toPlainText())
        for filename in os.listdir(self._folder_path.text()):
            try:
                with open(os.path.join(self._folder_path.text(), filename), "rb") as f:
                    matches = rule.match(data=f.read())
                    for match in matches:
                        strings = match.strings[0]
                        result[filename] = {
                            "path": self._folder_path.text(),
                            "addr": hex(strings[0]),
                            "rule_name": strings[1],
                            "value": strings[2].hex(),
                        }
            except IOError:  # Permission denied
                continue

        self._table.setRowCount(len(result))
        self._detect_count.setText(str(len(result)))

        for idx, (filename, value) in enumerate(result.items()):
            self._table.setItem(idx, 0, QtWidgets.QTableWidgetItem(value["path"]))
            self._table.setItem(idx, 1, QtWidgets.QTableWidgetItem(filename))
            self._table.setItem(idx, 2, QtWidgets.QTableWidgetItem(value["addr"]))
            self._table.setItem(idx, 3, QtWidgets.QTableWidgetItem(value["rule_name"]))
            self._table.setItem(idx, 4, QtWidgets.QTableWidgetItem(value["value"]))
        self.layout.addWidget(self._table)

    def _select_path(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            "Open a folder",
            os.path.expanduser("~"),
            QtWidgets.QFileDialog.ShowDirsOnly,
        )

        if path:
            self._folder_path.setText(path)