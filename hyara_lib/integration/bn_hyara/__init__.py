from .binaryninja_api import HyaraBinaryNinja

from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler
import PySide6.QtWidgets as QtWidgets
from PySide6.QtCore import Qt


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
