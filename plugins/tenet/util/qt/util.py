import sys
import time

from .shim import *

#------------------------------------------------------------------------------
# Qt Fonts
#------------------------------------------------------------------------------

def MonospaceFont():
    """
    Convenience alias for creating a monospace Qt font object.
    """
    font = QtGui.QFont("Courier New")
    font.setStyleHint(QtGui.QFont.TypeWriter)
    return font

#------------------------------------------------------------------------------
# Qt Util
#------------------------------------------------------------------------------

def copy_to_clipboard(data):
    """
    Copy the given data (a string) to the system clipboard.
    """
    cb = QtWidgets.QApplication.clipboard()
    cb.clear(mode=cb.Clipboard)
    cb.setText(data, mode=cb.Clipboard)

def flush_qt_events():
    """
    Flush the Qt event pipeline.
    """
    app = QtCore.QCoreApplication.instance()
    app.processEvents()

def focus_window():
    """
    Lame helper function to help with dev/debug.
    """
    mb = QtWidgets.QMessageBox(get_qmainwindow())
    mb.setText("Click to take focus...")
    mb.setStandardButtons(QtWidgets.QMessageBox.Ok)
    button = mb.button(QtWidgets.QMessageBox.Ok)
    mb.exec_()

def get_dpi_scale():
    """
    Get a DPI-afflicted value useful for consistent UI scaling.
    """
    font = MonospaceFont()
    font.setPointSize(normalize_font(120))
    fm = QtGui.QFontMetricsF(font)

    # xHeight is expected to be 40.0 at normal DPI
    return fm.height() / 173.0

def normalize_font(font_size):
    """
    Normalize the given font size based on the system DPI.
    """
    if sys.platform == "darwin": # macos is lame
        return font_size + 2
    return font_size

def get_qmainwindow():
    """
    Get the QMainWindow instance for the current Qt runtime.
    """
    app = QtWidgets.QApplication.instance()
    return [x for x in app.allWidgets() if x.__class__ is QtWidgets.QMainWindow][0]

def compute_color_on_gradient(percent, color1, color2):
    """
    Compute the color specified by a percent between two colors.
    """
    r1, g1, b1, _ = color1.getRgb()
    r2, g2, b2, _ = color2.getRgb()

    # compute the new color across the gradient of color1 -> color 2
    r = r1 + percent * (r2 - r1)
    g = g1 + percent * (g2 - g1)
    b = b1 + percent * (b2 - b1)

    # return the new color
    return QtGui.QColor(r,g,b)