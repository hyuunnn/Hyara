from .hyara_lib.integration.cutter_api import HyaraCutter
import PySide2.QtWidgets as QtWidgets
import cutter


class HyaraWidget(cutter.CutterDockWidget):
    def __init__(self, parent):
        super(HyaraWidget, self).__init__(parent)
        self.main = parent
        self.setObjectName("Hyara")
        self.setWindowTitle("Hyara")

        self.HyaraCutter = HyaraCutter()
        content = QtWidgets.QWidget()
        self.setWidget(content)
        content.setLayout(self.HyaraCutter.layout)


class HyaraPlugin(cutter.CutterPlugin):
    name = "Hyara Plugin"
    description = "Hyara"
    version = "2.1"
    author = "Hyun Yi @hyuunnn"
    hyaraWidget = None

    def setupPlugin(self):
        pass

    def setStartAddress(self):
        offset = int(self.startAddrAction.data())
        if offset:
            self.hyaraWidget.HyaraCutter._start_address.setText(hex(offset))
            self.hyaraWidget.HyaraCutter._variable_name.setText(f"str_{hex(offset)}")

    def setEndAddress(self):
        offset = int(self.endAddrAction.data())
        if offset:
            self.hyaraWidget.HyaraCutter._end_address.setText(hex(offset))

    def setupActions(self):
        self.startAddrAction = QtWidgets.QAction("Hyara - Select Start Address")
        self.endAddrAction = QtWidgets.QAction("Hyara - Select End Address")

        # Disassembly menu actions
        menu = self.hyaraWidget.main.getContextMenuExtensions(
            cutter.MainWindow.ContextMenuType.Disassembly
        )
        menu.addSeparator()
        menu.addAction(self.startAddrAction)
        menu.addAction(self.endAddrAction)
        self.startAddrAction.triggered.connect(self.setStartAddress)
        self.endAddrAction.triggered.connect(self.setEndAddress)

    def setupInterface(self, main):
        self.hyaraWidget = HyaraWidget(main)
        self.setupActions()
        main.addPluginDockWidget(self.hyaraWidget)

    def terminate(self):
        pass
