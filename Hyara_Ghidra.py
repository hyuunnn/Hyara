from hyara_lib.integration.ghidra_api import HyaraGhidra
import sys
try:
    import PySide2.QtWidgets as QtWidgets
except:
    import PySide6.QtWidgets as QtWidgets

class HyaraWidget(QtWidgets.QWidget):
    def __init__(self):
        QtWidgets.QWidget.__init__(self)

        self.HyaraGhidra = HyaraGhidra()
        self.setLayout(self.HyaraGhidra.layout)

def run():
    if not QtWidgets.QApplication.instance():
        app = QtWidgets.QApplication(sys.argv)
    else:
        app = QtWidgets.QApplication.instance()

    window = HyaraWidget()
    window.show()
    app.exec_()