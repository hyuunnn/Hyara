from sys import modules

PYQT_ENABLE = False
try:
    from PyQt5 import QtWidgets, QtCore, QtGui
    PYQT_ENABLE = True
except:
    pass

if PYQT_ENABLE == False:
    try:
        import PySide2.QtWidgets as QtWidgets
        import PySide2.QtCore as QtCore
        import PySide2.QtGui as QtGui
    except:
        import PySide6.QtWidgets as QtWidgets
        import PySide6.QtCore as QtCore
        import PySide6.QtGui as QtGui

from PIL import Image
from PIL.ImageQt import ImageQt
from functools import partial

import pefile
import io

ICON_HEADER = (
    b"\x00\x00\x01\x00\x01\x00\x30\x30\x00\x00\x01\x00\x08\x00\xA8\x0E\x00\x00\x16\x00\x00\x00"
)


class YaraIcon(QtWidgets.QDialog):
    def __init__(self, file_path, rule_list, _ui_populate_table):
        super(YaraIcon, self).__init__()
        self.setObjectName("YaraIcon")
        self.setWindowTitle("YaraIcon")
        self.file_path = file_path
        self.rule_list = rule_list
        self._ui_populate_table = _ui_populate_table

    def _ui_init(self):
        self._ui_setting()
        self._ui_init_layout()
        self._ui_clicked_connect()
        self.exec_()

    def _ui_setting(self):
        self._varable_name = QtWidgets.QLineEdit()
        self._start_offset = QtWidgets.QLineEdit()
        self._length = QtWidgets.QLineEdit()
        self._enter_button = QtWidgets.QPushButton("Enter")
        self._icon_data_list = self._get_icon()
        self._icon_rule_list = []
        self._enter_button_list = []

    def _ui_label_center(self, title):
        result = QtWidgets.QLabel(title)
        result.setAlignment(QtCore.Qt.AlignCenter)
        return result

    def _ui_set_pixmap(self, qimage):
        result = QtWidgets.QLabel()
        result.setPixmap(QtGui.QPixmap.fromImage(qimage))
        return result

    def _ui_init_layout(self):
        self.layout = QtWidgets.QVBoxLayout()
        GL0 = QtWidgets.QGridLayout()
        GL0.addWidget(QtWidgets.QLabel("Variable Name : "), 0, 0)
        GL0.addWidget(self._varable_name, 0, 1)
        GL0.addWidget(QtWidgets.QLabel("Start Offset : "), 0, 2)
        GL0.addWidget(self._start_offset, 0, 3)
        GL0.addWidget(QtWidgets.QLabel("Length : "), 0, 4)
        GL0.addWidget(self._length, 0, 5)
        GL0.addWidget(self._enter_button, 0, 6)
        self.layout.addLayout(GL0)

        GL1 = QtWidgets.QGridLayout()
        GL1.addWidget(self._ui_label_center("Icon"), 0, 0)
        GL1.addWidget(self._ui_label_center("Icon Size"), 0, 1)
        GL1.addWidget(self._ui_label_center("Rule"), 0, 2)
        GL1.addWidget(self._ui_label_center("Save Rule"), 0, 3)

        for idx, value in enumerate(self._icon_data_list):
            self._icon_rule_list.append(QtWidgets.QLineEdit())
            enter_button = QtWidgets.QPushButton("Enter")
            enter_button.clicked.connect(partial(self._yara_save_icon, idx))
            self._enter_button_list.append(enter_button)

            qimage = ImageQt(Image.open(io.BytesIO(ICON_HEADER + value["raw_data"])))
            GL1.addWidget(self._ui_set_pixmap(qimage), idx + 1, 0)
            GL1.addWidget(QtWidgets.QLabel(hex(value["size"])), idx + 1, 1)
            GL1.addWidget(self._icon_rule_list[idx], idx + 1, 2)
            GL1.addWidget(self._enter_button_list[idx], idx + 1, 3)

        self.layout.addLayout(GL1)
        self.setLayout(self.layout)

    def _ui_clicked_connect(self):
        self._enter_button.clicked.connect(self._yara_make_icon)

    def _get_icon(self):
        data = []
        pe = pefile.PE(self.file_path)
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.id == pefile.RESOURCE_TYPE["RT_ICON"]:
                for directory in entry.directory.entries:
                    for rsrc in directory.directory.entries:
                        offset = rsrc.data.struct.OffsetToData
                        size = rsrc.data.struct.Size
                        data.append(
                            {
                                "raw_data": pe.get_memory_mapped_image()[offset : offset + size],
                                "offset": offset,
                                "size": size,
                            }
                        )
        return data

    def _yara_make_icon(self):
        start_offset = int(self._start_offset.text(), 16)
        length = int(self._length.text(), 10)

        for idx, value in enumerate(self._icon_data_list):
            self._icon_rule_list[idx].setText(
                value["raw_data"][start_offset : start_offset + length].hex()
            )

    def _yara_save_icon(self, idx):
        variable_name = self._varable_name.text()
        rule_text = self._icon_rule_list[idx].text()
        start_offset = int(self._start_offset.text(), 16)
        end = start_offset + int(self._length.text(), 10)

        self.rule_list[variable_name] = {
            "text": rule_text,
            "start": str(start_offset),
            "end": str(end),
            "type": "icon",
        }

        self._ui_populate_table()
