from tenet.ui import *
from tenet.types import *
from tenet.util.qt.util import copy_to_clipboard
from tenet.integration.api import DockableWindow

#------------------------------------------------------------------------------
# hex.py -- Hex Dump Controller
#------------------------------------------------------------------------------
#
#    The purpose of this file is to house the 'headless' components of a
#    basic hex dump window and its underlying functionality. This is split
#    into a model and controller component, of a typical 'MVC' design pattern.
#
#    This provides much of the core logic behind both the memory and stack
#    views used by the plugin.
#

class HexController(object):
    """
    A generalized controller for Hex View based window.
    """

    def __init__(self, pctx):
        self.pctx = pctx
        self.model = HexModel(pctx)
        self.reader = None

        # UI components
        self.view = None
        self.dockable = None
        self._title = "<unassigned>"

        # signals
        self._ignore_signals = False
        pctx.breakpoints.model.breakpoints_changed(self._breakpoints_changed)

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

        self.view = HexView(self, self.model)
        new_dockable = DockableWindow(self._title, self.view)

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
        self.model.pointer_size = reader.arch.POINTER_SIZE

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
        Detach the trace reader from this controller.
        """
        self.reader = None
        self.model.reset()

    def navigate(self, address):
        """
        Navigate the hex view to a given address.
        """
        if address < 0:
            address = 0

        last_visible_address = address + self.model.data_size
        if last_visible_address > 0xFFFFFFFFFFFFFFFF:
            last_visible_address = 0xFFFFFFFFFFFFFFFF

        self.model.address = address

        #self.reset_selection(0)
        self.refresh_memory()

    def set_data_size(self, num_bytes):
        """
        Change the number of bytes to be held / displayed by the viewer.
        """
        self.model.data_size = num_bytes
        self.refresh_memory()

    def copy_selection(self, start_address, end_address):
        """
        Copy the selected range of bytes to the system clipboard.
        """
        assert end_address > start_address
        if not self.reader:
            return ''

        # fetch memory for the selected region
        num_bytes = end_address - start_address
        memory = self.reader.get_memory(start_address, num_bytes)

        # dump bytes to hex
        output = []
        for i in range(num_bytes):
            if memory.mask[i] == 0xFF:
                output.append("%02X" % memory.data[i])
            else:
                output.append("??")

        byte_string = ' '.join(output)
        copy_to_clipboard(byte_string)

        return byte_string

    def pin_memory(self, address, access_type=BreakpointType.ACCESS, length=1):
        """
        Pin a region of memory.
        """
        self._ignore_signals = True
        self.pctx.breakpoints.clear_memory_breakpoints()
        self.pctx.breakpoints.add_breakpoint(address, access_type, length)
        self._ignore_signals = False

    def refresh_memory(self):
        """
        Refresh the visible memory.
        """
        if not self.reader:
            self.model.data = None
            self.model.mask = None
            return

        memory = self.reader.get_memory(self.model.address, self.model.data_size)

        self.model.data = memory.data
        self.model.mask = memory.mask
        self.model.delta = self.reader.delta

        if self.view:
            self.view.refresh()

    def set_fade_threshold(self, address):
        """
        Change the threshold address that the view will begin to 'fade' its contents.

        This is used to 'fade' the unallocated region of the stack, for example.
        """
        self.model.fade_address = address

    #-------------------------------------------------------------------------
    # Callbacks
    #-------------------------------------------------------------------------

    def _idx_changed(self, idx):
        """
        The trace reader position has been changed.
        """
        self.refresh_memory()

    def _breakpoints_changed(self):
        """
        Handle breakpoints changed event.
        """
        if not self.view:
            return

        if self._ignore_signals:
            return

        self.view.refresh()

class HexModel(object):
    """
    A generalized model for Hex View based window.
    """

    def __init__(self, pctx):
        self._pctx = pctx

        # how the hex (data) and auxillary text should be displayed
        self._hex_format = HexType.BYTE
        self._aux_format = AuxType.ASCII

        # view settings
        self._num_bytes_per_line = 16

        # initialize the remaining model parameters
        self.reset()

    def reset(self):
        """
        Reset the model to a clean state.
        """

        # the 'cached' data to be displayed by the hex view
        self.data = None
        self.mask = None
        self.data_size = 0
        self.delta = None

        self.address = 0
        self.fade_address = 0

        # pinned memory / breakpoint selections
        self._pinned_selections = []

    #----------------------------------------------------------------------
    # Properties
    #----------------------------------------------------------------------

    @property
    def memory_breakpoints(self):
        """
        Return the set of active memory breakpoints.
        """
        return self._pctx.breakpoints.model.memory_breakpoints

    @property
    def num_bytes_per_line(self):
        """
        Return the number of bytes that should be displayed per line.
        """
        return self._num_bytes_per_line

    @num_bytes_per_line.setter
    def num_bytes_per_line(self, width):
        """
        Set the number of bytes to be displayed per line.
        """

        if width < 1:
            raise ValueError("Invalid bytes per line value (must be > 0)")

        if width % HEX_TYPE_WIDTH[self._hex_format]:
            raise ValueError("Bytes per line must be a multiple of display format type")

        self._num_bytes_per_line = width
        #self._refresh_view_settings()

    @property
    def hex_format(self):
        return self._hex_format

    @hex_format.setter
    def hex_format(self, value):
        if value == self._hex_format:
            return
        self._hex_format = value
        #self.refresh()

    @property
    def aux_format(self):
        return self._aux_format

    @aux_format.setter
    def aux_format(self, value):
        if value == self._aux_format:
            return
        self._aux_format = value
        #self.refresh()