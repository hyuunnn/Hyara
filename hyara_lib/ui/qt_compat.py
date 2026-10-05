"""Qt binding used by IDA, Cutter, Binary Ninja, and Ghidra."""

from sys import modules


def import_qt():
    """Return QtWidgets, QtCore, and QtGui for the current host."""
    if "idaapi" in modules:
        from PySide6 import QtCore, QtGui, QtWidgets

        return QtWidgets, QtCore, QtGui

    try:
        import PySide2.QtCore as QtCore
        import PySide2.QtGui as QtGui
        import PySide2.QtWidgets as QtWidgets
    except ImportError:
        import PySide6.QtCore as QtCore
        import PySide6.QtGui as QtGui
        import PySide6.QtWidgets as QtWidgets
    return QtWidgets, QtCore, QtGui
