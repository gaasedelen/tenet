import logging
import functools

import binaryninja
import binaryninja.mainthread as mainthread
import binaryninja.binaryview as binaryview


from .api import DisassemblerCoreAPI, DisassemblerContextAPI
from ...util.qt import *
from ...util.misc import is_mainthread

logger = logging.getLogger("Tenet.API.Binja")

def execute_sync(function, sync_type):
    """
    Synchronize with the disassembler for safe database access.

    Modified from https://github.com/vrtadmin/FIRST-plugin-ida
    """
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        output = [None]

        #
        # this inline function definition is technically what will execute
        # in the context of the main thread. we use this thunk to capture
        # any output the function may want to return to the user.
        #
        def thunk():
            output[0] = function(*args, **kwargs)
            return 1
        if is_mainthread():
            thunk()
        else:
            mainthread.execute_on_main_thread(thunk, sync_type)

        # return the output of the synchronized execution
        return output[0]
    return wrapper

class BinjaCoreAPI(DisassemblerCoreAPI):
    NAME = "Binja"

    def __init__(self):
        super(BinjaCoreAPI, self).__init__()
        self._dockabnle_factory = {}
        self._init_version()
    
    def _init_version(self):

        # Retrieve Binja's version #
        disassembler_verison = binaryninja.core_version_info()
        major, minor = disassembler_verison.major, disassembler_verison.minor

        # save the verison number components for later use
        self._version_major = major
        self._version_minor = minor
        self._version_patch = 0
    
    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @property
    def headless(self) -> bool:
        return not binaryninja.core_ui_enabled()

    #--------------------------------------------------------------------------
    # Synchronization Decorators
    #--------------------------------------------------------------------------

    @staticmethod
    def execute_read(function):
        return binaryninja.execute_on_main_thread_and_wait(function)

    @staticmethod
    def execute_write(function):
        return binaryninja.execute_on_main_thread_and_wait(function)

    @staticmethod
    def execute_ui(function):
        return binaryninja.execute_on_main_thread_and_wait(function)

    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    def get_disassembler_user_directory(self):
        return binaryninja.get_install_directory()
    #! Probably wrong thing to do, but don't think this is ever used
    def refresh_views(self):
        binaryninja.binaryview.update_analysis_and_wait()

    #? Don't know if we can
    def get_disassembly_background_color(self):
        """
        Get the background color of the Binja disassembly view.
        """

        # Get ActivePaneBackgroundColor
        color = binaryninja.ThemeColor(79)
        return color

    def is_msg_inited(self):
        #! May work?
        return binaryninja.is_output_redirected_to_log()

    @execute_ui.__func__
    def warning(self, text):
        super(BinjaCoreAPI, self).warning(text)

    @execute_ui.__func__
    def message(self, message):
        print(message)


    #--------------------------------------------------------------------------
    # UI API Shims
    #--------------------------------------------------------------------------
    #TODO This thing. UI in binja seems to suck
    def create_dockable(self, window_title, widget):

        # create a dockable widget, and save a reference to it for later use
        twidget = ida_kernwin.create_empty_widget(window_title)

        # cast the IDA 'twidget' as a Qt widget for use
        dockable = ida_kernwin.PluginForm.TWidgetToPyQtWidget(twidget)
        layout = dockable.layout()
        layout.addWidget(widget)

        # return the dockable QtWidget / container
        return dockable


#------------------------------------------------------------------------------
# Disassembler Context API (database-specific)
#------------------------------------------------------------------------------

class BinjaContextAPI(DisassemblerContextAPI):

    def __init__(self, dctx):
        super(BinjaContextAPI, self).__init__(dctx)

    @property
    def busy(self):
        return binaryview.AnalysisInfo.state != binaryview.AnalysisState.IdleState
