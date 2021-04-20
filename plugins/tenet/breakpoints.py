from tenet.ui import *
from tenet.types import BreakpointType, BreakpointEvent, TraceBreakpoint
from tenet.util.misc import register_callback, notify_callback
from tenet.integration.api import DockableWindow
from tenet.integration.api import disassembler

#------------------------------------------------------------------------------
# breakpoints.py -- Breakpoint Controller
#------------------------------------------------------------------------------
#
#    The purpose of this file is to house the 'headless' components of the
#    breakpoints window and its underlying functionality. This is split into
#    a model and controller component, of a typical 'MVC' design pattern. 
#
#    v0.1 NOTE/TODO: err, a dedicated bp window was planned but did not quite
#    make the cut for the initial release of this plugin. For that reason,
#    some of this logic may be half-baked pending further work.
#

class BreakpointController(object):
    """
    The Breakpoint Controller (Logic)
    """

    def __init__(self, pctx):
        self.pctx = pctx
        self.model = BreakpointModel()

        # UI components
        if QT_AVAILABLE:
            self.view = BreakpointView(self, self.model)
            self.dockable = DockableWindow("Trace Breakpoints", self.view)
        else:
            self.view = None
            self.dockable = None

        # events
        self._ignore_events = False
        self.pctx.core.ui_breakpoint_changed(self._ui_breakpoint_changed)

    def reset(self):
        """
        Reset the breakpoint controller.
        """
        self.focus_breakpoint(None)
        self.model.reset()

    def add_breakpoint(self, address, access_type):
        """
        Add a breakpoint of the given access type.
        """
        if access_type == BreakpointType.EXEC:
            self.add_execution_breakpoint(address)
        elif access_type == BreakpointType.READ:
            self.add_read_breakpoint(address)
        elif access_type == BreakpointType.WRITE:
            self.add_write_breakpoint(address)
        else:
            raise ValueError("UNKNOWN ACCESS TYPE", access_type)

    def add_execution_breakpoint(self, address):
        """
        Add an execution breakpoint for the given address.
        """
        self.model.bp_exec[address] = TraceBreakpoint(address, BreakpointType.EXEC)
    
    def add_read_breakpoint(self, address):
        """
        Add a memory read breakpoint for the given address.
        """
        self.model.bp_read[address] = TraceBreakpoint(address, BreakpointType.READ)

    def add_write_breakpoint(self, address):
        """
        Add a memory write breakpoint for the given address.
        """
        self.model.bp_write[address] = TraceBreakpoint(address, BreakpointType.WRITE)

    def focus_breakpoint(self, address, access_type=BreakpointType.NONE, length=1):
        """
        Set and focus on a given breakpoint.
        """
        dctx = disassembler[self.pctx]

        if self.model.focused_breakpoint and address != self.model.focused_breakpoint.address:
            self._ignore_events = True
            dctx.delete_breakpoint(self.model.focused_breakpoint.address)
            self._ignore_events = False

        if address is None:
            self.model.focused_breakpoint = None
            return None

        new_breakpoint = TraceBreakpoint(address, access_type, length)
        self.model.focused_breakpoint = new_breakpoint

        if access_type == BreakpointType.EXEC:
            self._ignore_events = True
            dctx.set_breakpoint(self.model.focused_breakpoint.address)
            self._ignore_events = False

        return new_breakpoint
         
    def _ui_breakpoint_changed(self, address, event_type):
        """
        Handle a breakpoint change event from the UI.
        """
        if self._ignore_events:
            return

        #print(f"UI Breakpoint Event {event_type} @ {address:08X}")

        if event_type == BreakpointEvent.ADDED:
            self.focus_breakpoint(address, BreakpointType.EXEC)

        elif event_type in [BreakpointEvent.DISABLED, BreakpointEvent.REMOVED]:
            self.focus_breakpoint(None)

class BreakpointModel(object):
    """
    The Breakpoint Model (Data)
    """

    def __init__(self):
        self.reset()

        #----------------------------------------------------------------------
        # Callbacks
        #----------------------------------------------------------------------

        self._focus_changed_callbacks = []

    def reset(self):
        self.bp_exec = {}
        self.bp_read = {}
        self.bp_write = {}
        self._focused_breakpoint = None

    @property
    def focused_breakpoint(self):
        return self._focused_breakpoint

    @focused_breakpoint.setter
    def focused_breakpoint(self, value):
        if value == self.focused_breakpoint:
            return
        self._focused_breakpoint = value
        self._notify_focused_breakpoint_changed(value)

    #----------------------------------------------------------------------
    # Callbacks
    #----------------------------------------------------------------------

    def focused_breakpoint_changed(self, callback):
        """
        Subscribe a callback for a breakpoint changed event.
        """
        register_callback(self._focus_changed_callbacks, callback)

    def _notify_focused_breakpoint_changed(self, breakpoint):
        """
        Notify listeners of a breakpoint changed event.
        """
        notify_callback(self._focus_changed_callbacks, breakpoint)
