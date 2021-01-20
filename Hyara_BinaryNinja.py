from hyara_lib.integration.binaryninja_api import HyaraBinaryNinja

import PySide2.QtWidgets as QtWidgets
from PySide2.QtCore import Qt
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler


class HyaraDockWidget(QtWidgets.QWidget, DockContextHandler):
    def __init__(self, parent, name, data):
        QtWidgets.QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        self.HyaraBinaryNinja = HyaraBinaryNinja()
        self.setLayout(self.HyaraBinaryNinja.layout)

    def shouldBeVisible(self, view_frame):
        if view_frame is None:
            return False
        else:
            return True

    def notifyViewChanged(self, view_frame):
        pass

    @staticmethod
    def create_widget(name, parent, data=None):
        return HyaraDockWidget(parent, name, data)


dock_handler = DockHandler.getActiveDockHandler()
dock_handler.addDockWidget(
    "Hyara",
    HyaraDockWidget.create_widget,
    Qt.BottomDockWidgetArea,
    Qt.Horizontal,
    False,
)
