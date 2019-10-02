import sys

import ida_funcs
import ida_kernwin

from PyQt5.QtCore import ( 
    QAbstractItemModel,
    QModelIndex,
    QObject,
    Qt,
)
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QStyledItemDelegate, QWidget
import sip

if sys.version_info > (3,):
    long = int

def ida_to_python(c):
    # IDA colors are 0xBBGGRR.
    r = (c & 255) / 255.0
    g = ((c >> 8) & 255) / 255.0
    b = ((c >> 16) & 255) / 255.0
    return r, g, b
def python_to_qt(r, g, b):
    # Qt colors are 0xRRGGBB
    r = int(r * 255) << 16
    g = int(g * 255) << 8
    b = int(b * 255)
    return 0xFF000000 | r | g | b



class Painter(QObject):
    class ProxyItemDelegate(QStyledItemDelegate):
        def __init__(self, delegate, model, parent=None):
            super(Painter.ProxyItemDelegate, self).__init__(parent)
            self._delegate = delegate
            self._model = model

        def paint(self, painter, option, index):
            index = self._model.index(index.row(), index.column())
            self._delegate.paint(painter, option, index)

    class ProxyItemModel(QAbstractItemModel):
        def __init__(self, model, user_manager, parent=None):
            super(Painter.ProxyItemModel, self).__init__(parent)
            self._model = model
            self._user_manager = user_manager

        def index(self, row, column, parent=QModelIndex()):
            return self.createIndex(row, column)

        def parent(self, index):
            index = self._model.index(index.row(), index.column())
            return self._model.parent(index)

        def rowCount(self):
            return self._model.rowCount()

        def columnCount(self):
            return self._model.columnCount()

        def data(self, index, role=Qt.DisplayRole):
            if role == Qt.BackgroundRole:
                func_ea = int(index.sibling(index.row(), 2).data(), 16)
                func = ida_funcs.get_func(func_ea)
                for user in self._user_manager.get_users():
                    if ida_funcs.func_contains(func, user["ea"]):
                        r, g, b = ida_to_python(user["color"])
                        return QColor(python_to_qt(r, g, b))
            index = self._model.index(index.row(), index.column())
            return self._model.data(index, role)

    def __init__(self, user_manager):
        super(Painter, self).__init__()
        self.user_manager = user_manager

        self._ida_nav_colorizer = None
        self._nbytes = 0

    def nav_colorizer(self, ea, nbytes):
        """This is the custom nav colorizer used by the painter."""
        self._nbytes = nbytes

        # There is a bug in IDA: with a huge number of segments, all the navbar
        # is colored with the user color. This will be resolved in IDA 7.2.
        users = self.user_manager.get_users()
        if users:
            for user in users:
                # Cursor color
                if ea - nbytes * 2 <= user["ea"] <= ea + nbytes * 2:
                    return long(user["color"])
                # Cursor borders
                if ea - nbytes * 4 <= user["ea"] <= ea + nbytes * 4:
                    return long(0)
        orig = ida_kernwin.call_nav_colorizer(
            self._ida_nav_colorizer, ea, nbytes
        )
        return long(orig)

    def ready_to_run(self):
        # The default nav colorized can only be recovered once!
        ida_nav_colorizer = ida_kernwin.set_nav_colorizer(self.nav_colorizer)
        if ida_nav_colorizer is not None:
            self._ida_nav_colorizer = ida_nav_colorizer
        self.refresh()

    def get_ea_hint(self, ea):
        users = self.user_manager.get_users()
        if not users:
            return None

        for user in users:
            start_ea = user["ea"] - self._nbytes * 4
            end_ea = user["ea"] + self._nbytes * 4
            # Check if the navbar range contains the user's address
            if start_ea <= ea <= end_ea:
                return str(user["user"])

    def get_bg_color(self, ea):
        # Check if disabled by the user
        users = self.user_manager.get_users()
        if not users:
            return None

        for user in users:
            if ea == user["ea"]:
                return user["color"]
        return None

    def widget_visible(self, twidget):
        widget = sip.wrapinstance(long(twidget), QWidget)
        if widget.windowTitle() != "Functions window":
            return
        table = widget.layout().itemAt(0).widget()

        # Replace the table's item delegate
        model = Painter.ProxyItemModel(table.model(), self._user_manager, self)
        old_deleg = table.itemDelegate()
        new_deleg = Painter.ProxyItemDelegate(old_deleg, model, self)
        table.setItemDelegate(new_deleg)

    def refresh(self):
        ida_kernwin.refresh_navband(True)
        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
        ida_kernwin.request_refresh(ida_kernwin.IWID_FUNCS)