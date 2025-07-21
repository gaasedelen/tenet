import abc
import logging

from ...util.qt import *

logger = logging.getLogger("Tenet.Integration.API")

#------------------------------------------------------------------------------
# Disassembler API
#------------------------------------------------------------------------------
#
#    the purpose of this file is to provide an abstraction layer for the more
#    generic disassembler APIs required by the plugin codebase. we strive to
#    use (or extend) this API for the bulk of our disassembler operations,
#    making the plugin as disassembler-agnostic as possible.
#
#    by subclassing the templated classes below, the plugin can support other
#    disassembler plaforms relatively easily. at the moment, implementing these
#    subclasses is ~50% of the work that is required to add support for this
#    plugin to any given interactive disassembler.
#
#    TODO: technically, a bunch of definitions are missing from this file
#    that are present in the IDA integration implementation. these will
#    need to be copied over to here to better define the disassembler API
#    dependencies required by this plugin
#

class DisassemblerCoreAPI(object):
    """
    An abstract implementation of the core disassembler APIs.
    """
    __metaclass__ = abc.ABCMeta

    # the name of the disassembler framework, eg 'IDA' or 'BINJA'
    NAME = NotImplemented

    @abc.abstractmethod
    def __init__(self):
        self._ctxs = {}

        # required version fields
        self._version_major = NotImplemented
        self._version_minor = NotImplemented
        self._version_patch = NotImplemented

        if not self.headless and QT_AVAILABLE:
            self._waitbox = WaitBox("Please wait...")
        else:
            self._waitbox = None

    def __delitem__(self, key):
        del self._ctxs[key]

    def __getitem__(self, key):
        return self._ctxs[key]

    def __setitem__(self, key, value):
        self._ctxs[key] = value

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    def version_major(self):
        """
        Return the major version number of the disassembler framework.
        """
        assert self._version_major != NotImplemented
        return self._version_major

    def version_minor(self):
        """
        Return the minor version number of the disassembler framework.
        """
        assert self._version_patch != NotImplemented
        return self._version_patch

    def version_patch(self):
        """
        Return the patch version number of the disassembler framework.
        """
        assert self._version_patch != NotImplemented
        return self._version_patch

    @abc.abstractproperty
    def headless(self):
        """
        Return a bool indicating if the disassembler is running without a GUI.
        """
        pass

    #--------------------------------------------------------------------------
    # Synchronization Decorators
    #--------------------------------------------------------------------------

    @staticmethod
    def execute_read(function):
        """
        Thread-safe function decorator to READ from the disassembler database.
        """
        raise NotImplementedError("execute_read() has not been implemented")

    @staticmethod
    def execute_write(function):
        """
        Thread-safe function decorator to WRITE to the disassembler database.
        """
        raise NotImplementedError("execute_write() has not been implemented")

    @staticmethod
    def execute_ui(function):
        """
        Thread-safe function decorator to perform UI disassembler actions.

        This function is generally used for executing UI (Qt) events from
        a background thread. as such, your implementation is expected to
        transfer execution to the main application thread where it is safe to
        perform Qt actions.
        """
        raise NotImplementedError("execute_ui() has not been implemented")

    #--------------------------------------------------------------------------
    # Disassembler Universal APIs
    #--------------------------------------------------------------------------

    @abc.abstractmethod
    def get_disassembler_user_directory(self):
        """
        Return the 'user' directory for the disassembler.
        """
        pass

    @abc.abstractmethod
    def get_disassembly_background_color(self):
        """
        Return the background color of the disassembly text view.
        """
        pass

    @abc.abstractmethod
    def is_msg_inited(self):
        """
        Return a bool if the disassembler output window is initialized.
        """
        pass

    def warning(self, text):
        """
        Display a warning dialog box with the given text.
        """
        msgbox = QtWidgets.QMessageBox()
        before = msgbox.sizeHint().width()
        msgbox.setIcon(QtWidgets.QMessageBox.Critical)
        after = msgbox.sizeHint().width()
        icon_width = after - before

        msgbox.setWindowTitle("Tenet Warning")
        msgbox.setText(text)

        font = msgbox.font()
        fm = QtGui.QFontMetricsF(font)
        text_width = fm.size(0, text).width()

        # don't ask...
        spacer = QtWidgets.QSpacerItem(int(text_width*1.1 + icon_width), 0, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        layout = msgbox.layout()
        layout.addItem(spacer, layout.rowCount(), 0, 1, layout.columnCount())
        msgbox.setLayout(layout)

        # show the dialog
        msgbox.exec_()

    @abc.abstractmethod
    def message(self, function_address, new_name):
        """
        Print a message to the disassembler console.
        """
        pass

    #--------------------------------------------------------------------------
    # UI APIs
    #--------------------------------------------------------------------------

    @abc.abstractmethod
    def create_dockable(self, dockable_name, widget):
        """
        Creates a dockable widget.
        """
        pass

    #------------------------------------------------------------------------------
    # WaitBox API
    #------------------------------------------------------------------------------

    def show_wait_box(self, text, modal=True):
        """
        Show the disassembler universal WaitBox.
        """
        assert QT_AVAILABLE, "This function can only be used in a Qt runtime"
        self._waitbox.set_text(text)
        self._waitbox.show(modal)

    def hide_wait_box(self):
        """
        Hide the disassembler universal WaitBox.
        """
        assert QT_AVAILABLE, "This function can only be used in a Qt runtime"
        self._waitbox.hide()

    def replace_wait_box(self, text):
        """
        Replace the text in the disassembler universal WaitBox.
        """
        assert QT_AVAILABLE, "This function can only be used in a Qt runtime"
        self._waitbox.set_text(text)

#------------------------------------------------------------------------------
# Disassembler Contextual API
#------------------------------------------------------------------------------

class DisassemblerContextAPI(object):
    """
    An abstract implementation of database/contextual disassembler APIs.
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __init__(self, dctx):
        self.dctx = dctx

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @abc.abstractproperty
    def busy(self):
        """
        Return a bool indicating if the disassembler is busy / processing.
        """
        pass

    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    def is_64bit(self):
        """
        Return True if the loaded processor module is 64bit.
        """
        pass

    @abc.abstractmethod
    def get_current_address(self):
        """
        Return the current cursor address in the open database.
        """
        pass

    @abc.abstractmethod
    def get_database_directory(self):
        """
        Return the directory for the open database.
        """
        pass

    @abc.abstractmethod
    def get_function_addresses(self):
        """
        Return all defined function addresses in the open database.
        """
        pass

    @abc.abstractmethod
    def get_function_name_at(self, address):
        """
        Return the name of the function at the given address.

        This is generally the user-facing/demangled name seen throughout the
        disassembler and is probably what you want to use for almost everything.
        """
        pass

    @abc.abstractmethod
    def get_function_raw_name_at(self, address):
        """
        Return the raw (eg, unmangled) name of the function at the given address.

        On the backend, most disassemblers store what is called the 'true' or
        'raw' (eg, unmangled) function name.
        """
        pass

    @abc.abstractmethod
    def get_imagebase(self):
        """
        Return the base address of the open database.
        """
        pass

    @abc.abstractmethod
    def get_root_filename(self):
        """
        Return the root executable (file) name used to generate the database.
        """
        pass

    @abc.abstractmethod
    def navigate(self, address, function_address=None):
        """
        Jump the disassembler UI to the given address.
        """
        pass

    @abc.abstractmethod
    def navigate_to_function(self, function_address, address):
        """
        Jump the disassembler UI to the given address, within a function.
        """
        pass

    @abc.abstractmethod
    def set_function_name_at(self, function_address, new_name):
        """
        Set the function name at given address.
        """
        pass