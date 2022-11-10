import ctypes
import logging

from binaryninja import PluginCommand
from binaryninjaui import UIAction, UIActionHandler, Menu

from tenet.integration.core import TenetCore
from tenet.types import BreakpointEvent
from tenet.context import TenetContext
from tenet.util.misc import register_callback, notify_callback, is_plugin_dev
from tenet.util.qt import *
from tenet.util.disassembler import disassembler

logger = logging.getLogger("Tenet.Binja.Integration")

#------------------------------------------------------------------------------
# Lighthouse Binja Integration
#---------------------------/DOckab---------------------------------------------------

class TenetBinja(TenetCore):
    """
    Tenet UI Integration for Binary Ninja.
    """

    def __init__(self):
        super(TenetBinja, self).__init__()
    #! Does this apply still?
    def get_context(self, dctx, startup=True):
        """
        Get the TenetContext object for a given database context.
        In Binary Ninja, a dctx is a BinaryView (BV).
        """
        dctx_id = ctypes.addressof(dctx.handle.contents)

        #
        # create a new LighthouseContext if this is the first time a context
        # has been requested for this BNDB / bv
        #

        if dctx_id not in self.contexts:

            # create a new 'context' representing this BNDB / bv
            lctx = TenetContext(self, dctx)
            if startup:
                lctx.start()

            # save the created ctx for future calls
            self.contexts[dctx_id] = lctx

        #
        # for binja, we basically *never* want to start the lighthouse ctx
        # when it is first created. this is because binja will *immediately*
        # create a coverage overview widget for every database when it is
        # first opened.
        #
        # this is annoying, because we don't want to actually start up all
        # of the lighthouse threads and subsystems unless the user actually
        # starts trying to use lighthouse for their session.
        #
        # so we initialize the lighthouse context (with start()) on the
        # second context request which will go throught the else block
        # below... any subsequent call to start() is effectively a nop!
        #

        else:
            lctx = self.contexts[dctx_id]
            lctx.start()

        # return the lighthouse context object for this database ctx / bv
        return lctx

    def binja_close_context(self, dctx):
        """
        Attempt to close / spin-down the LighthouseContext for the given dctx.
        In Binary Ninja, a dctx is a BinaryView (BV).
        """
        dctx_id = ctypes.addressof(dctx.handle.contents)

        # fetch the LighthouseContext for the closing BNDB
        try:
            lctx = self.lighthouse_contexts.pop(dctx_id)

        #
        # if lighthouse was not actually used for this BNDB / session, then
        # the lookup will fail as there is nothing to spindown
        #

        except KeyError:
            return

        # spin down the closing context (stop threads, cleanup qt state, etc)
        logger.info("Closing a LighthouseContext...")
        lctx.terminate()

    #--------------------------------------------------------------------------
    # UI Integration (Internal)
    #--------------------------------------------------------------------------

    #
    # TODO / HACK / XXX / V35: Some of Binja's UI elements (such as the
    # terminal) do not get assigned a BV, even if there is only one open.
    #
    # this is problematic, because if the user 'clicks' onto the termial, and
    # then tries to execute our UIActions (like 'Load Coverage File'), the
    # given 'context.binaryView' will be None
    #
    # in the meantime, we have to use this workaround that will try to grab
    # the 'current' bv from the dock. this is not ideal, but it will suffice.
    #
    # TODO <<<<<<<<<<<<<<<<<<
    def _interactive_load_trace(self, context):
        dctx = disassembler.binja_get_bv_from_dock()
        if not dctx:
            disassembler.warning("Lighthouse requires an open BNDB to load coverage.")
            return
        super()._interactive_load_trace(dctx)

    def _interactive_load_batch(self, context):
        dctx = disassembler.binja_get_bv_from_dock()
        if not dctx:
            disassembler.warning("Lighthouse requires an open BNDB to load coverage.")
            return
        super(TenetBinja, self).interactive_load_batch(dctx)

    def _open_coverage_xref(self, dctx, addr):
        super(TenetBinja, self).open_coverage_xref(addr, dctx)

    def _is_xref_valid(self, dctx, addr):

        #
        # this is a special case where we check if the ctx exists rather than
        # blindly creating a new one. again, this is because binja may call
        # this function at random times to decide whether it should display the
        # XREF menu option.
        #
        # but asking whether or not the xref menu option should be shown is not
        # a good indidication of 'is the user actually using lighthouse' so we
        # do not want this to be one that creates lighthouse contexts
        #

        dctx_id = ctypes.addressof(dctx.handle.contents)
        lctx = self.lighthouse_contexts.get(dctx_id, None)
        if not lctx:
            return False

        # return True if there appears to be coverage loaded...
        return bool(lctx.director.coverage_names)

    def _open_coverage_overview(self, context):
        dctx = disassembler.binja_get_bv_from_dock()
        if not dctx:
            disassembler.warning("Lighthouse requires an open BNDB to open the overview.")
            return
        super(TenetBinja, self).open_coverage_overview(dctx)

    #--------------------------------------------------------------------------
    # Binja Actions
    #--------------------------------------------------------------------------

    ACTION_LOAD_TRACE      = "Tenet\\load_trace"
    ACTION_FIRST_EXECUTION = "Tenet\\first_execution"
    ACTION_FINAL_EXECUTION = "Tenet\\final_execution"
    ACTION_NEXT_EXECUTION  = "Tenet\\next_execution"
    ACTION_PREV_EXECUTION  = "Tenet\\prev_execution"

    def _install_load_trace(self):
        action = self.ACTION_LOAD_TRACE
        UIAction.registerAction(action)
        UIActionHandler.globalActions().bindAction(action, UIAction(self._interactive_load_trace))
        Menu.mainMenu("Tools").addAction(action, "Loading", 0)
        logger.info("Installed the 'load_trace' menu entry")

    def _install_first_execution(self):
        action = self.ACTION_FIRST_EXECUTION
        UIAction.registerAction(action)
        UIActionHandler.globalActions().bindAction(action, UIAction(self._interactive_load_batch))
        Menu.mainMenu("Tools").addAction(action, "Loading", 1)
        logger.info("Installed the 'first_execution' menu entry")

    def _install_final_execution(self):
        action = self.ACTION_FINAL_EXECUTION
        UIAction.registerAction(action)
        UIActionHandler.globalActions().bindAction(action, UIAction(self._interactive_load_batch))
        Menu.mainMenu("Tools").addAction(action, "Loading", 1)
        logger.info("Installed the 'final_execution' menu entry")

    def _install_next_execution(self):
        action = self.ACTION_NEXT_EXECUTION
        UIAction.registerAction(action)
        UIActionHandler.globalActions().bindAction(action, UIAction(self._interactive_load_batch))
        Menu.mainMenu("Tools").addAction(action, "Loading", 1)
        logger.info("Installed the 'next_execution' menu entry")

    def _install_prev_execution(self):
        action = self.ACTION_PREV_EXECUTION
        UIAction.registerAction(action)
        UIActionHandler.globalActions().bindAction(action, UIAction(self._interactive_load_batch))
        Menu.mainMenu("Tools").addAction(action, "Loading", 1)
        logger.info("Installed the 'prev_execution' menu entry")


    # NOTE/V35: Binja doesn't really 'unload' plugins, so whatever...
    def _uninstall_load_file(self):
        pass
    def _uninstall_load_batch(self):
        pass
    def _uninstall_open_coverage_xref(self):
        pass
    def _uninstall_open_coverage_overview(self):
        pass


    #--------------------------------------------------------------------------
    # UI Event Handlers
    #--------------------------------------------------------------------------

    def _breakpoint_changed_hook(self, code, bpt):
        # """
        # (Event) Breakpoint changed.
        # """

        # if code == ida_dbg.BPTEV_ADDED:
        #     self._notify_ui_breakpoint_changed(bpt.ea, BreakpointEvent.ADDED)

        # elif code == ida_dbg.BPTEV_CHANGED:
        #     if bpt.enabled():
        #         self._notify_ui_breakpoint_changed(bpt.ea, BreakpointEvent.ENABLED)
        #     else:
        #         self._notify_ui_breakpoint_changed(bpt.ea, BreakpointEvent.DISABLED)

        # elif code == ida_dbg.BPTEV_REMOVED:
        #     self._notify_ui_breakpoint_changed(bpt.ea, BreakpointEvent.REMOVED)

        return 0

    def _popup_hook(self, widget, popup):
        # """
        # (Event) IDA is about to show a popup for the given TWidget.
        # """

        # # TODO: return if plugin/trace is not active
        # pass

        # # fetch the (IDA) window type (eg, disas, graph, hex ...)
        # view_type = ida_kernwin.get_widget_type(widget)

        # # only attach these context items to popups in disas views
        # if view_type == ida_kernwin.BWN_DISASMS:

        #     # prep for some shady hacks
        #     p_qmenu = ctypes.cast(int(popup), ctypes.POINTER(ctypes.c_void_p))[0]
        #     qmenu = sip.wrapinstance(int(p_qmenu), QtWidgets.QMenu)

        #     #
        #     # inject and organize the Tenet plugin actions
        #     #

        #     ida_kernwin.attach_action_to_popup(
        #         widget,
        #         popup,
        #         self.ACTION_NEXT_EXECUTION,  # The action ID (see above)
        #         "Rename",                    # Relative path of where to add the action
        #         ida_kernwin.SETMENU_APP      # We want to append the action after ^
        #     )

        #     #
        #     # this is part of our bodge to inject a plugin action submenu
        #     # at a specific location in the QMenu, cuz I don't think it's
        #     # actually possible with the native IDA API's (for groups...)
        #     #

        #     for action in qmenu.actions():
        #         if action.text() == "Go to next execution":

        #             # inject a group for the exta 'go to' actions
        #             goto_submenu = QtWidgets.QMenu("Go to...")
        #             qmenu.insertMenu(action, goto_submenu)

        #             # hold a Qt ref of the submenu so it doesn't GC
        #             self.__goto_submenu = goto_submenu
        #             break

        #     ida_kernwin.attach_action_to_popup(
        #         widget,
        #         popup,
        #         self.ACTION_FIRST_EXECUTION,     # The action ID (see above)
        #         "Go to.../",                     # Relative path of where to add the action
        #         ida_kernwin.SETMENU_APP          # We want to append the action after ^
        #     )

        #     ida_kernwin.attach_action_to_popup(
        #         widget,
        #         popup,
        #         self.ACTION_FINAL_EXECUTION,     # The action ID (see above)
        #         "Go to.../",                     # Relative path of where to add the action
        #         ida_kernwin.SETMENU_APP          # We want to append the action after ^
        #     )

        #     ida_kernwin.attach_action_to_popup(
        #         widget,
        #         popup,
        #         self.ACTION_PREV_EXECUTION,  # The action ID (see above)
        #         "Rename",                    # Relative path of where to add the action
        #         ida_kernwin.SETMENU_APP      # We want to append the action after ^
        #     )

        #     #
        #     # inject a seperator to help insulate our plugin action group
        #     #

        #     for action in qmenu.actions():
        #         if action.text() == "Go to previous execution":
        #             qmenu.insertSeparator(action)
        #             break
        pass

    def _render_lines(self, lines_out, widget, lines_in):
        # """
        # (Event) IDA is about to render code viewer lines.
        # """
        # widget_type = ida_kernwin.get_widget_type(widget)

        # if widget_type == ida_kernwin.BWN_DISASM:
        #     self._highlight_disassesmbly(lines_out, widget, lines_in)

        return

    def _highlight_disassesmbly(self, lines_out, widget, lines_in):
        # """
        # TODO/XXX this is pretty gross
        # """
        # ctx = self.get_context(IDA_GLOBAL_CTX)
        # if not ctx.reader:
        #     return
        
        # trail_length = 6

        # forward_color = self.palette.trail_forward
        # current_color = self.palette.trail_current
        # backward_color = self.palette.trail_backward

        # r, g, b, _ = current_color.getRgb()
        # current_color = 0xFF << 24 | b << 16 | g << 8 | r
        
        # step_over = False
        # modifiers = QtGui.QGuiApplication.keyboardModifiers()
        # step_over = bool(modifiers & QtCore.Qt.ShiftModifier)

        # forward_ips = ctx.reader.get_next_ips(trail_length, step_over)
        # backward_ips = ctx.reader.get_prev_ips(trail_length, step_over)

        # backward_trail, forward_trail = {}, {}

        # trails = [
        #     (backward_ips, backward_trail, backward_color), 
        #     (forward_ips, forward_trail, forward_color)
        # ]

        # for addresses, trail, color in trails:
        #     for i, address in enumerate(addresses):
        #         percent = 1.0 - ((trail_length - i) / trail_length)

        #         # convert to bgr
        #         r, g, b, _ = color.getRgb()
        #         ida_color = b << 16 | g << 8 | r
        #         ida_color |= (0xFF - int(0xFF * percent)) << 24

        #         # save the trail color
        #         rebased_address = ctx.reader.analysis.rebase_pointer(address)
        #         trail[rebased_address] = ida_color

        # current_address = ctx.reader.rebased_ip
        # if not ida_bytes.is_mapped(current_address):
        #     last_good_idx = ctx.reader.analysis.get_prev_mapped_idx(ctx.reader.idx)
        #     if last_good_idx != -1:

        #         # fetch the last instruction pointer to fall within the trace
        #         last_good_trace_address = ctx.reader.get_ip(last_good_idx)

        #         # convert the trace-based instruction pointer to one that maps to the disassembler
        #         current_address = ctx.reader.analysis.rebase_pointer(last_good_trace_address)

        # for section in lines_in.sections_lines:
        #     for line in section:
        #         address = line.at.toea()
                
        #         if address in backward_trail:
        #             color = backward_trail[address]
        #         elif address in forward_trail:
        #             color = forward_trail[address]
        #         elif address == current_address:
        #             color = current_color
        #         else:
        #             continue

        #         entry = ida_kernwin.line_rendering_output_entry_t(line, ida_kernwin.LROEF_FULL_LINE, color)
        #         lines_out.entries.push_back(entry)
        pass
    #----------------------------------------------------------------------
    # Callbacks
    #----------------------------------------------------------------------

    def ui_breakpoint_changed(self, callback):
        # register_callback(self._ui_breakpoint_changed_callbacks, callback)
        pass
    def _notify_ui_breakpoint_changed(self, address, code):
        # notify_callback(self._ui_breakpoint_changed_callbacks, address, code)
        pass
#------------------------------------------------------------------------------
# IDA UI Helpers
#------------------------------------------------------------------------------

class BinjaCtxEntry():
    """
    A minimal context menu entry class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        super(BinjaCtxEntry, self).__init__()
        self.action_function = action_function

    def activate(self, ctx):
        # """
        # Execute the embedded action_function when this context menu is invoked.

        # NOTE: We pass 'None' to the action function to act as the '
        # """
        # self.action_function(IDA_GLOBAL_CTX)
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return 1

#------------------------------------------------------------------------------
# IDA UI Event Hooks
#------------------------------------------------------------------------------

class DbgHooks():
    def dbg_bpt_changed(self, code, bpt):
        pass

class UIHooks():
    def get_lines_rendering_info(self, lines_out, widget, lines_in):
        pass
    def ready_to_run(self):
        pass
    def finish_populating_widget_popup(self, widget, popup):
        pass