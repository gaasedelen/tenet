import logging
import functools

#
# TODO: should probably cleanup / document this file a bit better.
#
# it's worth noting that most of this is based on the same shim layer
# used by lighthouse
#

import ida_ua
import ida_dbg
import ida_idp
import ida_pro
import ida_auto
import ida_nalt
import ida_name
import ida_xref
import idautils
import ida_bytes
import ida_idaapi
import ida_diskio
import ida_kernwin
import ida_segment
import ida_ida

from .api import DisassemblerCoreAPI, DisassemblerContextAPI
from ...util.qt import *
from ...util.misc import is_mainthread

logger = logging.getLogger("Tenet.API.IDA")

#------------------------------------------------------------------------------
# Utils
#------------------------------------------------------------------------------

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
            ida_kernwin.execute_sync(thunk, sync_type)

        # return the output of the synchronized execution
        return output[0]
    return wrapper

#------------------------------------------------------------------------------
# Disassembler Core API (universal)
#------------------------------------------------------------------------------

class IDACoreAPI(DisassemblerCoreAPI):
    NAME = "IDA"

    def __init__(self):
        super(IDACoreAPI, self).__init__()
        self._dockable_factory = {}
        self._init_version()

    def _init_version(self):

        # retrieve IDA's version #
        disassembler_version = ida_kernwin.get_kernel_version()
        major, minor = map(int, disassembler_version.split("."))

        # save the version number components for later use
        self._version_major = major
        self._version_minor = minor
        self._version_patch = 0

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @property
    def headless(self):
        return ida_kernwin.cvar.batch

    #--------------------------------------------------------------------------
    # Synchronization Decorators
    #--------------------------------------------------------------------------

    @staticmethod
    def execute_read(function):
        return execute_sync(function, ida_kernwin.MFF_READ)

    @staticmethod
    def execute_write(function):
        return execute_sync(function, ida_kernwin.MFF_WRITE)

    @staticmethod
    def execute_ui(function):
        return execute_sync(function, ida_kernwin.MFF_FAST)

    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    def get_disassembler_user_directory(self):
        return ida_diskio.get_user_idadir()

    def refresh_views(self):
        ida_kernwin.refresh_idaview_anyway()

    def get_disassembly_background_color(self):
        """
        Get the background color of the IDA disassembly view.
        """

        # create a donor IDA 'code viewer'
        viewer = ida_kernwin.simplecustviewer_t()
        viewer.Create("Colors")

        # get the viewer's qt widget
        viewer_twidget = viewer.GetWidget()
        viewer_widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(viewer_twidget)

        # fetch the background color property
        #viewer.Show() # TODO: re-enable!
        color = viewer_widget.property("line_bg_default")

        # destroy the view as we no longer need it
        #viewer.Close()

        # return the color
        return color

    def is_msg_inited(self):
        return ida_kernwin.is_msg_inited()

    @execute_ui.__func__
    def warning(self, text):
        super(IDACoreAPI, self).warning(text)

    @execute_ui.__func__
    def message(self, message):
        print(message)

    #--------------------------------------------------------------------------
    # UI API Shims
    #--------------------------------------------------------------------------

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

class IDAContextAPI(DisassemblerContextAPI):

    def __init__(self, dctx):
        super(IDAContextAPI, self).__init__(dctx)

    @property
    def busy(self):
        return not(ida_auto.auto_is_ok())

    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    @IDACoreAPI.execute_read
    def get_current_address(self):
        return ida_kernwin.get_screen_ea()

    def get_processor_type(self):
        ## get the target arch, PLFM_386, PLFM_ARM, etc # TODO
        #arch = idaapi.ph_get_id()
        pass

    def is_64bit(self):
        # The get_inf_structure() function is deprecated in newer IDA versions.
        # The 'inf' object is now directly accessible via ida_ida.
        return ida_ida.inf_is_64bit()

    def is_call_insn(self, address):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, address) and ida_idp.is_call_insn(insn):
            return True
        return False

    def get_instruction_addresses(self):
        """
        Return all instruction addresses from the executable.
        """
        instruction_addresses = []

        for seg_address in idautils.Segments():

            # fetch code segments
            seg = ida_segment.getseg(seg_address)
            if seg.sclass != ida_segment.SEG_CODE:
                continue

            current_address = seg_address
            end_address = seg.end_ea

            # save the address of each instruction in the segment
            while current_address < end_address:
                current_address = ida_bytes.next_head(current_address, end_address)
                if ida_bytes.is_code(ida_bytes.get_flags(current_address)):
                    instruction_addresses.append(current_address)

        #    print(f"Seg {seg.start_ea:08X} --> {seg.end_ea:08X} CODE")
        #print(f" -- {len(instruction_addresses):,} instructions found")

        return instruction_addresses

    def is_mapped(self, address):
        return ida_bytes.is_mapped(address)

    def get_next_insn(self, address):

        xb = ida_xref.xrefblk_t()
        ok = xb.first_from(address, ida_xref.XREF_ALL)

        while ok and xb.iscode:
            if xb.type == ida_xref.fl_F:
                return xb.to
            ok = xb.next_from()

        return -1

    def get_prev_insn(self, address):

        xb = ida_xref.xrefblk_t()
        ok = xb.first_to(address, ida_xref.XREF_ALL)

        while ok and xb.iscode:
            if xb.type == ida_xref.fl_F:
                return xb.frm
            ok = xb.next_to()

        return -1

    def get_database_directory(self):
        return idautils.GetIdbDir()

    def get_function_addresses(self):
        return list(idautils.Functions())

    def get_function_name_at(self, address):
        return ida_name.get_short_name(address)

    def get_function_raw_name_at(self, function_address):
        return ida_name.get_name(function_address)

    def get_imagebase(self):
        return ida_nalt.get_imagebase()

    def get_root_filename(self):
        return ida_nalt.get_root_filename()

    def navigate(self, address):

        # TODO fetch active view? or most recent one? i'm lazy for now...
        widget = ida_kernwin.find_widget("IDA View-A")

        #
        # this call can both navigate to an arbitrary address, and keep
        # the cursor position 'static' within the window at an (x,y)
        # text position
        #
        # TODO: I think it's kind of tricky to figure out the 'center' line of
        # the disassembly window navigation, so for now we'll just make a
        # navigation call always center around line 20...
        #

        CENTER_AROUND_LINE_INDEX = 20

        if widget:
            return ida_kernwin.ea_viewer_history_push_and_jump(widget, address, 0, CENTER_AROUND_LINE_INDEX, 0)

        # ehh, whatever.. just let IDA navigate to yolo
        else:
            return ida_kernwin.jumpto(address)

    def navigate_to_function(self, function_address, address):
        return self.navigate(address)

    def set_function_name_at(self, function_address, new_name):
        ida_name.set_name(function_address, new_name, ida_name.SN_NOWARN)
    
    def set_breakpoint(self, address):
        ida_dbg.add_bpt(address)

    def delete_breakpoint(self, address):
        ida_dbg.del_bpt(address)

#------------------------------------------------------------------------------
# HexRays Util
#------------------------------------------------------------------------------

def hexrays_available():
    """
    Return True if an IDA decompiler is loaded and available for use.
    """
    try:
        import ida_hexrays
        return ida_hexrays.init_hexrays_plugin()
    except ImportError:
        return False

def map_line2citem(decompilation_text):
    """
    Map decompilation line numbers to citems.

    This function allows us to build a relationship between citems in the
    ctree and specific lines in the hexrays decompilation text.

    Output:

        +- line2citem:
        |    a map keyed with line numbers, holding sets of citem indexes
        |
        |      eg: { int(line_number): sets(citem_indexes), ... }
        '

    """
    line2citem = {}

    #
    # it turns out that citem indexes are actually stored inline with the
    # decompilation text output, hidden behind COLOR_ADDR tokens.
    #
    # here we pass each line of raw decompilation text to our crappy lexer,
    # extracting any COLOR_ADDR tokens as citem indexes
    #

    for line_number in range(decompilation_text.size()):
        line_text = decompilation_text[line_number].line
        line2citem[line_number] = lex_citem_indexes(line_text)

    return line2citem

def map_line2node(cfunc, metadata, line2citem):
    """
    Map decompilation line numbers to node (basic blocks) addresses.

    This function allows us to build a relationship between graph nodes
    (basic blocks) and specific lines in the hexrays decompilation text.

    Output:

        +- line2node:
        |    a map keyed with line numbers, holding sets of node addresses
        |
        |      eg: { int(line_number): set(nodes), ... }
        '

    """
    line2node = {}
    treeitems = cfunc.treeitems
    function_address = cfunc.entry_ea

    #
    # prior to this function, a line2citem map was built to tell us which
    # citems reside on any given line of text in the decompilation output.
    #
    # now, we walk through this line2citem map one 'line_number' at a time in
    # an effort to resolve the set of graph nodes associated with its citems.
    #

    for line_number, citem_indexes in line2citem.items():
        nodes = set()

        #
        # we are at the level of a single line (line_number). we now consume
        # its set of citems (citem_indexes) and attempt to identify explicit
        # graph nodes they claim to be sourced from (by their reported EA)
        #

        for index in citem_indexes:

            # get the code address of the given citem
            try:
                item = treeitems[index]
                address = item.ea

            # apparently this is a thing on IDA 6.95
            except IndexError as e:
                continue

            # find the graph node (eg, basic block) that generated this citem
            node = metadata.get_node(address)

            # address not mapped to a node... weird. continue to the next citem
            if not node:
                #logger.warning("Failed to map node to basic block")
                continue

            #
            # we made it this far, so we must have found a node that contains
            # this citem. save the computed node_id to the list of known
            # nodes we have associated with this line of text
            #

            nodes.add(node.address)

        #
        # finally, save the completed list of node ids as identified for this
        # line of decompilation text to the line2node map that we are building
        #

        line2node[line_number] = nodes

    # all done, return the computed map
    return line2node

def lex_citem_indexes(line):
    """
    Lex all ctree item indexes from a given line of text.

    The HexRays decompiler output contains invisible text tokens that can
    be used to attribute spans of text to the ctree items that produced them.

    This function will simply scrape and return a list of all the these
    tokens (COLOR_ADDR) which contain item indexes into the ctree.

    """
    i = 0
    indexes = []
    line_length = len(line)

    # lex COLOR_ADDR tokens from the line of text
    while i < line_length:

        # does this character mark the start of a new COLOR_* token?
        if line[i] == idaapi.COLOR_ON:

            # yes, so move past the COLOR_ON byte
            i += 1

            # is this sequence for a COLOR_ADDR?
            if ord(line[i]) == idaapi.COLOR_ADDR:

                # yes, so move past the COLOR_ADDR byte
                i += 1

                #
                # A COLOR_ADDR token is followed by either 8, or 16 characters
                # (a hex encoded number) that represents an address/pointer.
                # in this context, it is actually the index number of a citem
                #

                citem_index = int(line[i:i+idaapi.COLOR_ADDR_SIZE], 16)
                i += idaapi.COLOR_ADDR_SIZE

                # save the extracted citem index
                indexes.append(citem_index)

                # skip to the next iteration as i has moved
                continue

        # nothing we care about happened, keep lexing forward
        i += 1

    # return all the citem indexes extracted from this line of text
    return indexes

class DockableWindow(ida_kernwin.PluginForm):

    def __init__(self, title, widget):
        super(DockableWindow, self).__init__()
        self.title = title
        self.widget = widget

        self.visible = False
        self._dock_position = None
        self._dock_target = None

        if ida_pro.IDA_SDK_VERSION < 760:
            self.__dock_filter = IDADockSizeHack()

    def OnCreate(self, form):
        #print("Creating", self.title)
        self.parent = self.FormToPyQtWidget(form)

        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.widget)
        self.parent.setLayout(layout)

        if ida_pro.IDA_SDK_VERSION < 760:
            self.__dock_size_hack()

    def OnClose(self, foo):
        self.visible = False
        #print("Closing", self.title)

    def __dock_size_hack(self):
        if self.widget.minimumWidth() == 0:
            return
        self.widget.min_width = self.widget.minimumWidth()
        self.widget.max_width = self.widget.maximumWidth()
        self.widget.setMinimumWidth(self.widget.min_width // 2)
        self.widget.setMaximumWidth(self.widget.min_width // 2)
        self.widget.installEventFilter(self.__dock_filter)

    def show(self):
        dock_position = self._dock_position

        if ida_pro.IDA_SDK_VERSION < 760:
            WOPN_SZHINT = 0x200
        
            # create the dockable widget, without actually showing it
            self.Show(self.title, options=ida_kernwin.PluginForm.WOPN_CREATE_ONLY)

            # use some kludge to display our widget, and enforce the use of its sizehint
            ida_widget = self.GetWidget()
            ida_kernwin.display_widget(ida_widget, WOPN_SZHINT)
            self.visible = True

        # no hax required for IDA 7.6 and newer
        else:
            self.Show(self.title)
            self.visible = True
            dock_position |= ida_kernwin.DP_SZHINT

        # move the window to a given location if specified
        if dock_position is not None:
            ida_kernwin.set_dock_pos(self.title, self._dock_target, dock_position)

    def hide(self):
        self.Close(1)

    def set_dock_position(self, dest_ctrl=None, position=0):
        self._dock_target = dest_ctrl
        self._dock_position = position

        if not self.visible:
            return

        ida_kernwin.set_dock_pos(self.title, dest_ctrl, position)

    def copy_dock_position(self, other):
        self._dock_target = other._dock_target
        self._dock_position = other._dock_position

class IDADockSizeHack(QtCore.QObject):
    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.WindowActivate:
            obj.setMinimumWidth(obj.min_width)
            obj.setMaximumWidth(obj.max_width)
            obj.removeEventFilter(self)
        return False