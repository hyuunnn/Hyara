from .hyara_lib.integration.cutter_api import HyaraCutter
import PySide2.QtWidgets as QtWidgets
import cutter


class HyaraWidget(cutter.CutterDockWidget):
    def __init__(self, parent):
        super(HyaraWidget, self).__init__(parent)
        self.setObjectName("Hyara")
        self.setWindowTitle("Hyara")

        self.HyaraCutter = HyaraCutter()
        content = QtWidgets.QWidget()
        self.setWidget(content)
        content.setLayout(self.HyaraCutter.layout)


class HyaraPlugin(cutter.CutterPlugin):
    name = "Hyara Plugin"
    description = "Hyara"
    version = "1.0"
    author = "Hyun Yi @hyuunnn"

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        widget = HyaraWidget(main)
        main.addPluginDockWidget(widget)

    def terminate(self):
        pass