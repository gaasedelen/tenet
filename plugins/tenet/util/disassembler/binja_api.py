# -*- coding: utf-8 -*-
import os
import sys
import logging
import functools
import threading
import collections

from .api import DisassemblerCoreAPI, DisassemblerContextAPI
from ...util.qt import *
from ...util.misc import is_mainthread, not_mainthread

import binaryninja
from binaryninja import PythonScriptingInstance, binaryview
from binaryninja.plugin import BackgroundTaskThread

logger = logging.getLogger("Tenet.API.Binja")

#------------------------------------------------------------------------------
# Utils
#------------------------------------------------------------------------------

def execute_sync(function):
    """
    Synchronize with the disassembler for safe database access.
    """

    @functools.wraps(function)
    def wrapper(*args, **kwargs):

        #
        # in Binary Ninja, it is only safe to access the BNDB from a thread
        # that is *not* the mainthread. if we appear to already be in a
        # background thread of some sort, simply execute the given function
        #

        if not is_mainthread():
            return function(*args, **kwargs)

        #
        # if we are in the mainthread, we need to schedule a background
        # task to perform our database task/function instead
        #
        # this inline function definition is technically what will execute
        # in a database-safe background thread. we use this thunk to
        # capture any output the function may want to return to the user.
        #

        output = [None]
        def thunk():
            output[0] = function(*args, **kwargs)
            return 1

        class DatabaseRead(BackgroundTaskThread):
            """
            A stub task to safely read from the BNDB.
            """
            def __init__(self, text, function):
                super(DatabaseRead, self).__init__(text, False)
                self._task_to_run = function
            def run(self):
                self._task_to_run()
                self.finish()

        # schedule the databases read and wait for its completion
        t = DatabaseRead("Accessing database...", thunk)
        t.start()
        t.join()

        # return the output of the synchronized execution / read
        return output[0]
    return wrapper

class BinjaCoreAPI(DisassemblerCoreAPI):
    NAME = "BINJA"

    def __init__(self):
        super(BinjaCoreAPI, self).__init__()
        self._init_version()
    
    def _init_version(self):
        version_string = binaryninja.core_version()

        # retrieve Binja's version #
        if "-" in version_string: # dev
            disassembler_version = version_string.split("-", 1)[0]
        else: # commercial, personal
            disassembler_version = version_string.split(" ", 1)[0]

        major, minor, patch, *_= disassembler_version.split(".") + ['0']

        # save the version number components for later use
        self._version_major = major
        self._version_minor = minor
        self._version_patch = patch
    
    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @property
    def headless(self) -> bool:
        return not(binaryninja.core_ui_enabled())

    #--------------------------------------------------------------------------
    # Synchronization Decorators
    #--------------------------------------------------------------------------

    @staticmethod
    def execute_read(function):
        return execute_sync(function)

    @staticmethod
    def execute_write(function):
        return execute_sync(function)

    @staticmethod
    def execute_ui(function):

        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            ff = functools.partial(function, *args, **kwargs)

            # if we are already in the main (UI) thread, execute now
            if is_mainthread():
                ff()
                return

            # schedule the task to run in the main thread
            binaryninja.execute_on_main_thread(ff)

        return wrapper
    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    def get_disassembler_user_directory(self):
        return os.path.split(binaryninja.user_plugin_path())[0]

    def get_disassembly_background_color(self):
        return binaryninjaui.getThemeColor(binaryninjaui.ThemeColor.LinearDisassemblyBlockColor)

    def is_msg_inited(self):
        return True

    @execute_ui.__func__
    def warning(self, text):
        super(BinjaCoreAPI, self).warning(text)

    def message(self, message):
        print(message)

    # Dunno if binja has to do this or what
    def refresh_views(self):
        pass

    #--------------------------------------------------------------------------
    # UI API Shims
    #--------------------------------------------------------------------------

    def register_dockable(self, dockable_name, create_widget_callback):
        dock_handler = DockHandler.getActiveDockHandler()
        dock_handler.addDockWidget(dockable_name, create_widget_callback, QtCore.Qt.RightDockWidgetArea, QtCore.Qt.Horizontal, False)

    def create_dockable_widget(self, parent, dockable_name):
        return DockableWindow(parent, dockable_name)

    def show_dockable(self, dockable_name):
        dock_handler = DockHandler.getActiveDockHandler()
        dock_handler.setVisible(dockable_name, True)

    def hide_dockable(self, dockable_name):
        dock_handler = DockHandler.getActiveDockHandler()
        dock_handler.setVisible(dockable_name, False)

    #TODO These are in a bad spot
    def show_registers(self, register_controller):
        register_controller.show()
    
    def show_memory(self, memory_controller):
        memory_controller.show()
    
    def show_stack(self, stack_controller):
        stack_controller.show()
    #--------------------------------------------------------------------------
    # XXX Binja Specfic Helpers
    #--------------------------------------------------------------------------

    def binja_get_bv_from_dock(self):
        dh = DockHandler.getActiveDockHandler()
        if not dh:
            return None
        vf = dh.getViewFrame()
        if not vf:
            return None
        vi = vf.getCurrentViewInterface()
        bv = vi.getData()
        return bv

#------------------------------------------------------------------------------
# Disassembler Context API (database-specific)
#------------------------------------------------------------------------------

class BinjaContextAPI(DisassemblerContextAPI):

    def __init__(self, dctx):
        super(BinjaContextAPI, self).__init__(dctx)
        self.bv = dctx
        self.bp_tag = self.bv.create_tag_type("breakpoint", "🔴")

    @property
    def busy(self):
        return binaryview.AnalysisInfo.state != binaryview.AnalysisState.IdleState

    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    def get_current_address(self):

        # TODO/V35: this doen't work because of the loss of context bug...
        #ctx = UIContext.activeContext()
        #ah = ctx.contentActionHandler()
        #ac = ah.actionContext()
        #return ac.address

        dh = DockHandler.getActiveDockHandler()
        if not dh:
            return 0
        vf = dh.getViewFrame()
        if not vf:
            return 0
        ac = vf.actionContext()
        if not ac:
            return 0
        return ac.address

    @BinjaCoreAPI.execute_read
    def get_database_directory(self):
        return os.path.dirname(self.bv.file.filename)

    @not_mainthread
    def get_function_addresses(self):
        return [x.start for x in self.bv.functions]

    def get_function_name_at(self, address):
        func = self.bv.get_function_at(address)
        if not func:
            return None
        return func.symbol.short_name

    @BinjaCoreAPI.execute_read
    def get_function_raw_name_at(self, address):
        func = self.bv.get_function_at(address)
        if not func:
            return None
        return func.name

    @not_mainthread
    def get_imagebase(self):
        return self.bv.start

    @not_mainthread
    def get_root_filename(self):
        return os.path.basename(self.bv.file.original_filename)

    def navigate(self, address):
        return self.bv.navigate(self.bv.view, address)

    def navigate_to_function(self, function_address, address):

        #
        # attempt a more 'precise' jump, that guarantees to place us within
        # the given function. this is necessary when trying to jump to an
        # an address/node that is shared between two functions
        #

        funcs = self.bv.get_functions_containing(address)
        if not funcs:
            return False

        #
        # try to find the function that contains our target (address) and has
        # a matching function start...
        #

        for func in funcs:
            if func.start == function_address:
                break

        # no matching function ???
        else:
            return False

        dh = DockHandler.getActiveDockHandler()
        vf = dh.getViewFrame()
        vi = vf.getCurrentViewInterface()

        return vi.navigateToFunction(func, address)

    @BinjaCoreAPI.execute_write
    def set_function_name_at(self, function_address, new_name):
        func = self.bv.get_function_at(function_address)
        if not func:
            return
        if new_name == "":
            new_name = None
        func.name = new_name

    def is_64bit(self) -> bool:
        return self.bv.address_size & 8

    def is_arm(self) -> bool:
        arch = self.bv.arch.name.lower()
        if 'thumb' in arch or 'arm' in arch:
            return True
        return False

    def is_call_insn(self, address):
        functions = binaryview.get_functions_containing(address)
        if functions[0].is_call_instruction(address):
            return True
        return False

    #TODO make this faster...
    def get_instruction_addresses(self) -> list:
        """
        Return all instruction addresses from the executable.
        """
        instruction_addresses = []
        for name,section in self.bv.sections.items():
            if not self.bv.is_offset_code_semantics(section.start):        
                continue        
            # Iterate through disassembly and check if is valid instruction        
            current_address = 0    
            cursor = self.bv.get_linear_disassembly_position_at(section.start)    
            while current_address < section.end:        
                lines = self.bv.get_next_linear_disassembly_lines(cursor)        
                for line in lines:            
                    if line.type == binaryninja.enums.LinearDisassemblyLineType.CodeDisassemblyLineType.value:                
                        instruction_addresses.append(line.contents.address)            
                    current_address = line.contents.address
        return instruction_addresses
    #! Not sure how binja will deal with heap addresses and stuff
    def is_mapped(self, address):
        for seg in self.bv.segments:
            if seg.start < address < seg.end:
                return True
        return False


    #TODO <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    # def get_next_insn(self, address):

    #     xb = ida_xref.xrefblk_t()
    #     ok = xb.first_from(address, ida_xref.XREF_ALL)

    #     while ok and xb.iscode:
    #         if xb.type == ida_xref.fl_F:
    #             return xb.to
    #         ok = xb.next_from()

    #     return -1
    #TODO <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    # def get_prev_insn(self, address):

    #     xb = ida_xref.xrefblk_t()
    #     ok = xb.first_to(address, ida_xref.XREF_ALL)

    #     while ok and xb.iscode:
    #         if xb.type == ida_xref.fl_F:
    #             return xb.frm
    #         ok = xb.next_to()

    #     return -1

    # From binja debugger api 
    #! Not sure what tag type to use
    def set_breakpoint(self, address):
        function.create_user_data_tag(address,self.bp_tag, unique=True)

    def delete_breakpoint(self, address):
        function.remove_user_data_tags_of_type(address,self.bp_tag)

    # def delete_all_breakpoints(self):
    #     pass
    #--------------------------------------------------------------------------
    # Hooks API
    #--------------------------------------------------------------------------

    def create_rename_hooks(self):
        return RenameHooks(self.bv)

    #------------------------------------------------------------------------------
    # Function Prefix API
    #------------------------------------------------------------------------------

    PREFIX_SEPARATOR = "▁" # Unicode 0x2581

#------------------------------------------------------------------------------
# Hooking
#------------------------------------------------------------------------------

class RenameHooks(binaryview.BinaryDataNotification):
    """
    A hooking class to catch symbol changes in Binary Ninja.
    """

    def __init__(self, bv):
        self._bv = bv
        self.symbol_added = self.__symbol_handler
        self.symbol_updated = self.__symbol_handler
        self.symbol_removed = self.__symbol_handler

    def hook(self):
        self._bv.register_notification(self)

    def unhook(self):
        self._bv.unregister_notification(self)

    def __symbol_handler(self, view, symbol):
        func = self._bv.get_function_at(symbol.address)
        if not func or not func.start == symbol.address:
            return
        self.name_changed(symbol.address, symbol.name)

    def name_changed(self, address, name):
        """
        A placeholder callback, which will get hooked / replaced once live.
        """
        pass


#------------------------------------------------------------------------------
# UI
#------------------------------------------------------------------------------

if QT_AVAILABLE:
    import binaryninjaui
    from binaryninjaui import DockHandler, DockContextHandler, UIContext, UIActionHandler

    class DockableWindow(QtWidgets.QWidget,DockContextHandler):
        """
        A dockable Qt widget for Binary Ninja.
        """

        def __init__(self, title, widget):
            # self.dock_handler = DockHandler.getActiveDockHandler()
            # self.actionHandler = UIActionHandler()
            # self.actionHandler.setupActionHandler(self)
            self.title = title
            self.widget = widget

            self.visible = False
            self._dock_position = None
            self._dock_target = None

            # self._active_view = None
            # self._visible_for_view = collections.defaultdict(lambda: False)

        def OnCreate(self, form):
            # #print("Creating", self.title)
            # self.parent = self.FormToPyQtWidget(form)

            # layout = QtWidgets.QVBoxLayout()
            # layout.setContentsMargins(0, 0, 0, 0)
            # layout.addWidget(self.widget)
            # self.parent.setLayout(layout)
            print('Oncreate')
            pass

        def set_dock_position(self, dest_ctrl=None, position=0):
            self._dock_target = dest_ctrl
            self._dock_position = position

            if not self.visible:
                return

        def show(self):
            dock_position = self._dock_position


            # self.dock_handler.addDockWidget(self.title, self.widget, QtCore.Qt.RightDockWidgetArea, QtCore.Qt.Horizontal, False)
            # self.dock_handler.setVisible(self.title, True)
            # print(type(self.widget))
            # print(type(self.widget.parent))

            # Need to create a dockable widget

            print('testtestestsefsjfasfksdfkdsjlfasdkj')
            pass