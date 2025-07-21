import itertools

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
#    v0.2 NOTE/TODO: Currently, the breakpoint controller/Tenet artificially
#    limits usage to one execution breakpoint and one memory breakpoint at
#    a time. I'll probably raise this 'limit' when a proper gui is made
#    for managing and differentiating between breakpoints...
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
        self._ignore_signals = False
        self.pctx.core.ui_breakpoint_changed(self._ui_breakpoint_changed)

    def reset(self):
        """
        Reset the breakpoint controller.
        """
        self.model.reset()

    def add_breakpoint(self, address, access_type, length=1):
        """
        Add a breakpoint of the given access type.
        """
        if access_type == BreakpointType.EXEC:
            self.add_execution_breakpoint(address, length)
        elif access_type == BreakpointType.READ:
            self.add_read_breakpoint(address, length)
        elif access_type == BreakpointType.WRITE:
            self.add_write_breakpoint(address, length)
        elif access_type == BreakpointType.ACCESS:
            self.add_access_breakpoint(address, length)
        else:
            raise ValueError("UNKNOWN ACCESS TYPE", access_type)

    def add_execution_breakpoint(self, address):
        """
        Add an execution breakpoint for the given address.
        """
        self.model.bp_exec[address] = TraceBreakpoint(address, BreakpointType.EXEC)
        self.model._notify_breakpoints_changed()

    def add_read_breakpoint(self, address, length=1):
        """
        Add a memory read breakpoint for the given address.
        """
        self.model.bp_read[address] = TraceBreakpoint(address, BreakpointType.READ, length)
        self.model._notify_breakpoints_changed()

    def add_write_breakpoint(self, address, length=1):
        """
        Add a memory write breakpoint for the given address.
        """
        self.model.bp_write[address] = TraceBreakpoint(address, BreakpointType.WRITE, length)
        self.model._notify_breakpoints_changed()

    def add_access_breakpoint(self, address, length=1):
        """
        Add a memory access breakpoint for the given address.
        """
        self.model.bp_access[address] = TraceBreakpoint(address, BreakpointType.ACCESS, length)
        self.model._notify_breakpoints_changed()

    def clear_breakpoints(self):
        """
        Clear all breakpoints.
        """
        self.model.bp_exec = {}
        self.model.bp_read = {}
        self.model.bp_write = {}
        self.model.bp_access = {}
        self.model._notify_breakpoints_changed()

    def clear_execution_breakpoints(self):
        """
        Clear all execution breakpoints.
        """
        self.model.bp_exec = {}
        self.model._notify_breakpoints_changed()

    def clear_memory_breakpoints(self):
        """
        Clear all memory breakpoints.
        """
        self.model.bp_read = {}
        self.model.bp_write = {}
        self.model.bp_access = {}
        self.model._notify_breakpoints_changed()

    def _ui_breakpoint_changed(self, address, event_type):
        """
        Handle a breakpoint change event from the UI.
        """
        if self._ignore_signals:
            return

        self._delete_disassembler_breakpoints()
        self.model.bp_exec = {}

        if event_type in [BreakpointEvent.ADDED, BreakpointEvent.ENABLED]:
            self.add_execution_breakpoint(address)

        self.model._notify_breakpoints_changed()

    def _delete_disassembler_breakpoints(self):
        """
        Remove all execution breakpoints from the disassembler UI.
        """
        dctx = disassembler[self.pctx]

        self._ignore_signals = True
        for address in self.model.bp_exec:
            dctx.delete_breakpoint(address)
        self._ignore_signals = False

class BreakpointModel(object):
    """
    The Breakpoint Model (Data)
    """

    def __init__(self):
        self.reset()

        #----------------------------------------------------------------------
        # Callbacks
        #----------------------------------------------------------------------

        self._breakpoints_changed_callbacks = []

    def reset(self):
        self.bp_exec = {}
        self.bp_read = {}
        self.bp_write = {}
        self.bp_access = {}

    @property
    def memory_breakpoints(self):
        """
        Return an iterable list of all memory breakpoints.
        """
        bps = itertools.chain(
            self.bp_read.values(),
            self.bp_write.values(),
            self.bp_access.values()
        )
        return bps

    #----------------------------------------------------------------------
    # Callbacks
    #----------------------------------------------------------------------

    def breakpoints_changed(self, callback):
        """
        Subscribe a callback for a breakpoint changed event.
        """
        register_callback(self._breakpoints_changed_callbacks, callback)

    def _notify_breakpoints_changed(self):
        """
        Notify listeners of a breakpoint changed event.
        """
        notify_callback(self._breakpoints_changed_callbacks)
