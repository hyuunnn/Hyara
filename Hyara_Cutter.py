from .hyara_lib.integration.cutter_api import HyaraCutter
import PySide2.QtWidgets as QtWidgets
import cutter


class MyDockWidget(cutter.CutterDockWidget):
    def __init__(self, parent):
        super(MyDockWidget, self).__init__(parent)
        self.setObjectName("Hyara")
        self.setWindowTitle("Hyara")

        self.HyaraCutter = HyaraCutter()
        content = QtWidgets.QWidget()
        self.setWidget(content)
        content.setLayout(self.HyaraCutter.layout)


class YaraPlugin(cutter.CutterPlugin):
    name = "Hyara Plugin"
    description = "Hyara"
    version = "1.0"
    author = "Hyun Yi @hyuunnn"

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        widget = MyDockWidget(main)
        main.addPluginDockWidget(widget)

    def terminate(self):
        pass