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
from ...util.disassembler import disassembler
import binaryninjaui
from binaryninjaui import DockHandler, DockContextHandler, UIContext, UIActionHandler, SidebarWidgetType
from binaryninjaui import Sidebar, SidebarWidget, SidebarWidgetType, SidebarWidgetContainer, Sidebar
from binaryninjaui import GlobalAreaWidget, GlobalArea, UIActionHandler

import binaryninja
from binaryninja import PythonScriptingInstance, binaryview
from binaryninja.plugin import BackgroundTaskThread
from PySide6.QtCore import Qt, QRectF, QMetaType
from PySide6.QtGui import QImage, QPainter, QFont, QColor
from PySide6.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, \
    QLabel, QWidget

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
    def is_mapped(self, address):
        bv = self.binja_get_bv_from_dock()

        for seg in bv.segments:
            if seg.start < address < seg.end:
                return True
        return False

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
        print("Created binja context")
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
        functions = self.bv.get_functions_containing(address)
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

    # ! This is so shitty. Why doesn't linear disassmely also give the address
    def get_next_insn(self, address):
        pos = self.bv.get_linear_disassembly_position_at(address)
        for i,line in enumerate(pos.lines):            
            if len(line.contents.tokens) == 0:
                continue
            #     return -1
            # else:
            current_address = line.contents.address 
            if current_address == address:
                if i == len(pos.lines)-1:
                    pos.next()
                    next_insn = pos.lines[0].contents.address
                else:
                    next_insn = pos.lines[i+1].contents.address
                return next_insn
    #! Also shitty
    def get_prev_insn(self, address):
        pos = self.bv.get_linear_disassembly_position_at(address)
        for i,line in enumerate(pos.lines):            
            if len(line.contents.tokens) == 0:
                continue
            # if line.type != binaryninja.enums.LinearDisassemblyLineType.CodeDisassemblyLineType.value:                
            #     return -1
            # else:
            current_address = line.contents.address 
            if current_address == address:
                if i == 0:
                    pos.previous()
                    prev_insn = pos.lines[-1].contents.address
                else:
                    prev_insn = pos.lines[i-1].contents.address
                return prev_insn
    # From binja debugger api 
    #! Not sure what tag type to use
    def set_breakpoint(self, address):
        print("Setting breakpoint")
        self.bv.add_user_data_tag(address,self.bp_tag, unique=True)

    def delete_breakpoint(self, address):
        self.bv.remove_user_data_tags_of_type(address,self.bp_tag)

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


    class DockableWindow(DockContextHandler, QtWidgets.QWidget):
        """
        A dockable Qt widget for Binary Ninja.
        """

        def __init__(self, name, widget):
            self.qw = get_qmainwindow()
            self.dock_handler = self.qw.findChild(DockHandler, '__DockHandler')
            self.name = name
            self.widget = widget

            QtWidgets.QWidget.__init__(self, self.qw)
            DockContextHandler.__init__(self, self, name)

            # self.actionHandler = UIActionHandler()
            # self.actionHandler.setupActionHandler(self)



            self._active_view = None
            self._visible_for_view = collections.defaultdict(lambda: False)

            layout = QtWidgets.QVBoxLayout()
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(self.widget)
            self.setLayout(layout)

        @property
        def visible(self):
            return self._visible_for_view[self._active_view]

        @visible.setter
        def visible(self, is_visible):
            self._visible_for_view[self._active_view] = is_visible

        def show(self):
            dock_handler = self.qw.findChild(DockHandler, '__DockHandler')
            dock_handler.addDockWidget(self, Qt.BottomDockWidgetArea, Qt.Horizontal, True)


        def shouldBeVisible(self, view_frame):
            if not view_frame:
                return False

            if USING_PYSIDE6:
                import shiboken6 as shiboken
            else:
                import shiboken2 as shiboken

            vf_ptr = shiboken.getCppPointer(view_frame)[0]
            return self._visible_for_view[vf_ptr]

        def notifyVisibilityChanged(self, is_visible):
            self.visible = is_visible

        def notifyViewChanged(self, view_frame):
            if not view_frame:
                self._active_view = None
                return

            if USING_PYSIDE6:
                import shiboken6 as shiboken
            else:
                import shiboken2 as shiboken

            self._active_view = shiboken.getCppPointer(view_frame)[0]

            if self.visible:
                dock_handler = DockHandler.getActiveDockHandler()
                dock_handler.setVisible(self.m_name, True)


    class RegistersSidebarWidget(SidebarWidget):
        def __init__(self, name, widget):
            SidebarWidget.__init__(self, name)
            self.name = name
            self.widget = widget
            layout = QtWidgets.QVBoxLayout()
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(self.widget)
            self.setLayout(layout)


        def notifyOffsetChanged(self, offset):
            # self.offset.setText(hex(offset))
            return

        def notifyViewChanged(self, view_frame):
            # if view_frame is None:
            #     self.datatype.setText("None")
            #     self.data = None
            # else:
            #     self.datatype.setText(view_frame.getCurrentView())
            #     view = view_frame.getCurrentViewInterface()
            #     self.data = view.getData()
            return

        def contextMenuEvent(self, event):
            self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

    class RegistersSidebarWidgetType(SidebarWidgetType):
        def __init__(self, name, widget):

            self.name = name
            self.widget = widget

            # Sidebar icons are 28x28 points. Should be at least 56x56 pixels for
            # HiDPI display compatibility. They will be automatically made theme
            # aware, so you need only provide a grayscale image, where white is
            # the color of the shape.
            icon = QImage(56, 56, QImage.Format_RGB32)
            icon.fill(0)

            # Render an "H" as the example icon
            p = QPainter()
            p.begin(icon)
            p.setFont(QFont("Open Sans", 56))
            p.setPen(QColor(255, 255, 255, 255))
            p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "R")
            p.end()

            SidebarWidgetType.__init__(self, icon, "Registers")

        def show(self):
            Sidebar.addSidebarWidgetType(self)
            dh = DockHandler.getActiveDockHandler()
            vf = dh.getViewFrame()
            sb = vf.getSidebar()
            sb.activate(self)
            # Sidebar.activate(self)

        def createWidget(self, frame, data):
            # This callback is called when a widget needs to be created for a given context. Different
            # widgets are created for each unique BinaryView. They are created on demand when the sidebar
            # widget is visible and the BinaryView becomes active.
            self.registerssidebarwidget = RegistersSidebarWidget(self.name, self.widget)
            return self.registerssidebarwidget


    class StackSidebarWidget(SidebarWidget):
        def __init__(self, name, widget):
            SidebarWidget.__init__(self, name)
            self.name = name
            self.widget = widget
            layout = QtWidgets.QVBoxLayout()
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(self.widget)
            self.setLayout(layout)



        def notifyViewChanged(self, view_frame):
            # if view_frame is None:
            #     self.datatype.setText("None")
            #     self.data = None
            # else:
            #     self.datatype.setText(view_frame.getCurrentView())
            #     view = view_frame.getCurrentViewInterface()
            #     self.data = view.getData()
            return

        def contextMenuEvent(self, event):
            self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

    class StackMiniGraphWidgetType(SidebarWidgetType):
        def __init__(self, name, widget):

            self.name = name
            self.widget = widget

            # Sidebar icons are 28x28 points. Should be at least 56x56 pixels for
            # HiDPI display compatibility. They will be automatically made theme
            # aware, so you need only provide a grayscale image, where white is
            # the color of the shape.
            icon = QImage(56, 56, QImage.Format_RGB32)
            icon.fill(0)

            # Render an "H" as the example icon
            p = QPainter()
            p.begin(icon)
            p.setFont(QFont("Open Sans", 56))
            p.setPen(QColor(255, 255, 255, 255))
            p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "S")
            p.end()

            SidebarWidgetType.__init__(self, icon, "Stack")

        def show(self):
            Sidebar.addSidebarWidgetType(self)
            dh = DockHandler.getActiveDockHandler()
            vf = dh.getViewFrame()
            sb = vf.getSidebar()
            sb.activate(self)
            # Sidebar.activate(self)

        def isInReferenceArea(self):
            return True

        def createWidget(self, frame, data):
            # This callback is called when a widget needs to be created for a given context. Different
            # widgets are created for each unique BinaryView. They are created on demand when the sidebar
            # widget is visible and the BinaryView becomes active.
            self.stacksidebarwidget = StackSidebarWidget(self.name, self.widget)
            return self.stacksidebarwidget



    class MemoryGlobalAreaWidget(GlobalAreaWidget):
        def __init__(self, name, widget):
            print(GlobalArea.current())
            GlobalAreaWidget.__init__(self, name)
            self.actionHandler = UIActionHandler()
            self.actionHandler.setupActionHandler(self)
            self.name = name
            self.widget = widget
            layout = QtWidgets.QVBoxLayout()
            layout.addStretch()
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(self.widget)
            self.setLayout(layout)


        def notifyOffsetChanged(self, offset):
            self.offset.setText(hex(offset))
            # return

        def show(self):
            GlobalArea.addWidget(lambda context: self)
            # ga = ac.globalArea()
            pass
            # global_area = GlobalArea.toggle_visible()

        def notifyViewChanged(self, view_frame):
            if view_frame is None:
                self.datatype.setText("None")
                self.data = None
            else:
                self.datatype.setText(view_frame.getCurrentView())
                view = view_frame.getCurrentViewInterface()
                self.data = view.getData()
            # return

        def contextMenuEvent(self, event):
            self.m_contextMenuManager.show(self.m_menu, self.actionHandler)
