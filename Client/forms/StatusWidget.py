from PyQt5.QtCore import QPoint, QRect, QSize, Qt, QTimer
from PyQt5.QtGui import QIcon, QImage, QPainter, QPixmap, QRegion
from PyQt5.QtWidgets import QAction, QActionGroup, QLabel, QMenu, QWidget
import os.path
import constants
import colorsys

def get_rec_path(image_name):
     file = os.path.abspath(os.path.dirname(__file__))
     return "{0}\\{1}".format(file, image_name)

class StatusWidget(QWidget):
    @staticmethod
    def ida_to_python(c):
        # IDA colors are 0xBBGGRR.
        r = (c & 255) / 255.0
        g = ((c >> 8) & 255) / 255.0
        b = ((c >> 16) & 255) / 255.0
        return r, g, b

    @staticmethod
    def python_to_qt(r, g, b):
        # Qt colors are 0xRRGGBB
        r = int(r * 255) << 16
        g = int(g * 255) << 8
        b = int(b * 255)
        return 0xFF000000 | r | g | b

    @staticmethod
    def make_icon(template, color):
        """
        Create an icon for the specified user color. It will be used to
        generate on the fly an icon representing the user.
        """
        # Get a light and dark version of the user color
        r, g, b = StatusWidget.ida_to_python(color)
        h, l, s = colorsys.rgb_to_hls(r, g, b)
        r, g, b = colorsys.hls_to_rgb(h, 0.5, 1.0)
        light = StatusWidget.python_to_qt(r, g, b)
        r, g, b = colorsys.hls_to_rgb(h, 0.25, 1.0)
        dark = StatusWidget.python_to_qt(r, g, b)

        # Replace the icon pixel with our two colors
        image = QImage(template)
        for x in range(image.width()):
            for y in range(image.height()):
                c = image.pixel(x, y)
                if (c & 0xFFFFFF) == 0xFFFFFF:
                    image.setPixel(x, y, light)
                if (c & 0xFFFFFF) == 0x000000:
                    image.setPixel(x, y, dark)
        return QPixmap(image)

    def __init__(self, user_manager):
        super(StatusWidget, self).__init__()
        self._user_manager = user_manager

        def new_label():
            widget = QLabel()
            widget.setAutoFillBackground(False)
            widget.setAttribute(Qt.WA_PaintOnScreen)
            widget.setAttribute(Qt.WA_TranslucentBackground)
            return widget

        self._users_text_widget = new_label()
        self._users_icon = new_label()

        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)

        self._timer = QTimer()
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self.paint)

    def install(self, window):
        window.statusBar().addPermanentWidget(self)
        self._timer.start()
        self.paint()

    def uninstall(self, window):
        window.statusBar().removeWidget(self)
        self._timer.stop()

    def _context_menu(self, point):
        user_width = self._users_icon.sizeHint().width() + 3
        user_width += self._users_text_widget.sizeHint().width() + 3
        if point.x() < user_width + 3:
            self._users_context_menu(point)

    def _users_context_menu(self, point):
        menu = QMenu()
        template = QImage(get_rec_path("user.png"))
        users = self._user_manager.get_users()
        if users:
            menu.addSeparator()
            for user in users:
                text = "Name: %s" % user["user"]
                if user["logged"]:
                    pixmap = StatusWidget.make_icon(template, constants.GREEN_COLOR)
                else:
                    pixmap = StatusWidget.make_icon(template, constants.RED_COLOR)
                action = QAction(text, menu)
                action.setCheckable(False)
                action.setIcon(QIcon(pixmap))
                menu.addAction(action)
        menu.exec_(self.mapToGlobal(point))

    def paint(self):

        users = len(self._user_manager.get_users())
        self._users_text_widget.setText("Users | %d" % users)
        self._users_text_widget.adjustSize()

        users_icon = QPixmap(QImage(get_rec_path("users.png")))
        self._users_icon.setPixmap(users_icon.scaled(
            self._users_text_widget.sizeHint().height(),
            self._users_text_widget.sizeHint().height(),
            Qt.KeepAspectRatio,
            Qt.SmoothTransformation
        ))

        self.updateGeometry()   

    def sizeHint(self):
        width = 3 + self._users_text_widget.sizeHint().width()
        width += 3 + self._users_icon.sizeHint().width()

        return QSize(width, self._users_text_widget.sizeHint().height())

    def paintEvent(self, event):
        dpr = self.devicePixelRatioF()
        buffer = QPixmap(self.width() * dpr, self.height() * dpr)
        buffer.setDevicePixelRatio(dpr)
        buffer.fill(Qt.transparent)
        painter = QPainter(buffer)
        # Paint the users text widget
        x =  0
        region = QRegion(
            QRect(QPoint(0, 0), self._users_text_widget.sizeHint())
        )
        self._users_text_widget.render(painter, QPoint(0, 0), region)
         #Paint the users icon widget
        region = QRegion(
            QRect(QPoint(0, 0), self._users_icon.sizeHint())
        )
        x += self._users_text_widget.sizeHint().width() + 3
        self._users_icon.render(painter, QPoint(x, 0), region)
        painter.end()

        painter = QPainter(self)
        painter.drawPixmap(event.rect(), buffer, buffer.rect())
        painter.end()

    
    