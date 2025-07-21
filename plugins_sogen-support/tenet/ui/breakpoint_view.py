#
# TODO: I don't think this file is even in use right now, but w/e
# we'll ship it for now...
#

from tenet.util.qt import *

class BreakpointDock(QtWidgets.QDockWidget):
    """
    Dockable wrapper of a Breakpoint view.
    """
    def __init__(self, view, parent=None):
        super(BreakpointDock, self).__init__(parent)
        self.setAllowedAreas(QtCore.Qt.AllDockWidgetAreas)
        self.setWindowTitle("Breakpoints")
        self.setWidget(view)

class BreakpointView(QtWidgets.QWidget):
    """
    The Breakpoint Widget (UI)
    """

    def __init__(self, controller, model, parent=None):
        super(BreakpointView, self).__init__(parent)
        self.controller = controller
        self.model = model
        self._init_ui()
    
    def _init_ui(self):
        self.setMinimumHeight(100)

        self._init_table()

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._table)

    def _init_table(self):
        self._table = QtWidgets.QTableWidget(self)
        self._table.insertColumn(0)
        self._table.insertColumn(1)
        self._table.insertColumn(2)
        self._table.insertColumn(3)
        self._table.setHorizontalHeaderLabels(["Type", "Enabled", "Address", "Delete"])

