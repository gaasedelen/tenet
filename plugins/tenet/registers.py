from tenet.ui import *
from tenet.types import BreakpointType
from tenet.util.misc import register_callback, notify_callback
from tenet.integration.api import DockableWindow

#------------------------------------------------------------------------------
# registers.py -- Register Controller
#------------------------------------------------------------------------------
#
#    The purpose of this file is to house the 'headless' components of the
#    registers window and its underlying functionality. This is split into a 
#    model and controller component, of a typical 'MVC' design pattern. 
#
#    NOTE: for the time being, this file also contains the logic for the 
#    'IDX Shell' as it is kind of attached to the register view and not big
#    enough to demand its own seperate structuring ... yet
#

class RegisterController(object):
    """
    The Registers Controller (Logic)
    """

    def __init__(self, pctx):
        self.pctx = pctx
        self.reader = None
        self.model = RegistersModel(self.pctx.arch)

        # UI components
        self.view = None
        self.dockable = None

        # events 
        pctx.breakpoints.model.focused_breakpoint_changed(self._focused_breakpoint_changed)

    def show(self, target=None, position=0):
        """
        Make the window attached to this controller visible.
        """

        # if there is no Qt (eg, our UI framework...) then there is no UI
        if not QT_AVAILABLE:
            return

        # the UI has already been created, and is also visible. nothing to do
        if (self.dockable and self.dockable.visible):
            return

        #
        # if the UI has not yet been created, or has been previously closed
        # then we are free to create new UI elements to take the place of
        # anything that once was
        #

        self.view = RegisterView(self, self.model)
        new_dockable = DockableWindow("CPU Registers", self.view)

        #
        # if there is a reference to a left over dockable window (e.g, from a 
        # previous close of this window type) steal its dock positon so we can
        # hopefully take the same place as the old one
        #

        if self.dockable:
            new_dockable.copy_dock_position(self.dockable)
        elif (target or position):
            new_dockable.set_dock_position(target, position)

        # make the dockable/widget visible
        self.dockable = new_dockable
        self.dockable.show()

    def hide(self):
        """
        Hide the window attached to this controller.
        """

        # if there is no view/dockable, then there's nothing to try and hide
        if not(self.view and self.dockable):
            return

        # hide the dockable, and drop references to the widgets
        self.dockable.hide()
        self.view = None
        self.dockable = None
    
    def attach_reader(self, reader):
        """
        Attach a trace reader to this controller.
        """
        self.reader = reader

        # attach trace reader signals to this controller / window
        reader.idx_changed(self._idx_changed)

        #
        # directly call our event handler quick with the current idx since
        # it's the first time we're seeing this. this ensures that our widget
        # will accurately reflect the current state of the reader
        #

        self._idx_changed(reader.idx)

    def detach_reader(self):
        """
        Detach the active trace reader from this controller.
        """
        self.reader = None
        self.model.reset()

    def focus_register_value(self, reg_name):
        """
        Focus a register value in the register view.
        """

        # if the instruction pointer is selected, show its executions in the trace
        if reg_name == self.model.arch.IP:
            reg_value = self.model.registers[reg_name]
            self.pctx.breakpoints.focus_breakpoint(reg_value, BreakpointType.EXEC)
        else:
            self.clear_register_focus()

        self.model.focused_reg_value = reg_name
    
    def focus_register_name(self, reg_name):
        """
        Focus a register name in the register view.
        """
        self._clear_register_value_focus()
        self.model.focused_reg_name = reg_name

    def clear_register_focus(self):
        """
        Clear all focus on register fields.
        """
        self._clear_register_value_focus()
        self.model.focused_reg_name = None

    def follow_in_dump(self, reg_name):
        """
        Follow a given register value in the memory dump.
        """
        address = self.model.registers[reg_name]
        self.pctx.memory.navigate(address)

    def _clear_register_value_focus(self):
        """
        Clear focus from the active register field.
        """
        if self.model.focused_reg_value == self.model.arch.IP:
            assert self.pctx.breakpoints.model.focused_breakpoint
            assert self.pctx.breakpoints.model.focused_breakpoint.address == self.model.registers[self.model.arch.IP]
            self.pctx.breakpoints.focus_breakpoint(None)
        self.model.focused_reg_value = None

    def set_registers(self, registers, delta=None):
        """
        Set the registers for the view.
        """
        self.model.set_registers(registers, delta)

    def navigate_to_expression(self, expression):
        """
        Evaluate the expression in the IDX Shell and navigate to it.
        """

        # a target idx was given as an integer
        if isinstance(expression, int):
            target_idx = expression

        # string handling
        elif isinstance(expression, str):

            # blank string was passed from the shell, nothing to do...
            if not expression:
                return

            # a 'command' / alias idx was entered into the shell ('!...' prefix)
            if expression[0] == '!':

                #
                # for now, we only support 'one' command which is going to
                # let you seek to a position in the trace by percentage
                #
                #    eg: !0, or !100 to skip to the start/end of trace
                #

                try:
                    target_percent = float(expression[1:])
                except:
                    return

                # seek to the desired percentage
                self.reader.seek_percent(target_percent)
                return

            #
            # not a command, how about a comma seperated timestamp?
            # -- e.g '5,218,121'
            #

            idx_str = expression.replace(',', '')
            try:
                target_idx = int(idx_str)
            except:
                return

        else:
            raise ValueError(f"Unknown input expression type '{expression}'?!?")

        # seek to the desired idx
        self.reader.seek(target_idx)

    def _idx_changed(self, idx):
        """
        The trace position has been changed.
        """
        IP = self.model.arch.IP
        target = self.pctx.breakpoints.model.focused_breakpoint
        registers = self.pctx.reader.registers

        if target and target.address == registers[IP]:
            self.model.focused_reg_value = IP
        else:
            self.model.focused_reg_value = None

        self.model.idx = idx
        self.set_registers(self.reader.registers, self.reader.trace.get_reg_delta(idx).keys())

    def _focused_breakpoint_changed(self, breakpoint):
        """
        The focused breakpoint has changed.
        """
        if not self.view:
            return

        if not (breakpoint and breakpoint.type == BreakpointType.EXEC):
            self.model.focused_reg_value = None
            self.view.refresh()
            return

        IP = self.model.arch.IP
        registers = self.pctx.reader.registers

        if registers[IP] != breakpoint.address:
            self.model.focused_reg_value = None
            self.view.refresh()
            return

        self.model.focused_reg_value = IP
        self.view.refresh()

class RegistersModel(object):
    """
    The Registers Model (Data)
    """

    def __init__(self, arch):
        self.arch = arch
        self.reset()

        #----------------------------------------------------------------------
        # Callbacks
        #----------------------------------------------------------------------

        self._registers_changed_callbacks = []

    def reset(self):
        self.idx = -1
        self.delta = []
        self.registers = {}

        self.focused_reg_name = None
        self.focused_reg_value = None

    def set_registers(self, registers, delta=None):
        self.registers = registers
        self.delta = delta if delta else []
        self._notify_registers_changed()

    #----------------------------------------------------------------------
    # Callbacks
    #----------------------------------------------------------------------

    def registers_changed(self, callback):
        """
        Subscribe a callback for a registers changed event.
        """
        register_callback(self._registers_changed_callbacks, callback)

    def _notify_registers_changed(self):
        """
        Notify listeners of a registers changed event.
        """
        notify_callback(self._registers_changed_callbacks)
