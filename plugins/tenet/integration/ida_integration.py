import ctypes
import logging

#
# TODO: should probably cleanup / document this file a bit better
#

import ida_dbg
import ida_bytes
import ida_idaapi
import ida_kernwin

from tenet.core import TenetCore
from tenet.types import BreakpointEvent
from tenet.context import TenetContext
from tenet.util.misc import register_callback, notify_callback, is_plugin_dev
from tenet.util.qt import *

logger = logging.getLogger("Tenet.IDA.Integration")

IDA_GLOBAL_CTX = "blah this value doesn't matter"

#------------------------------------------------------------------------------
# IDA UI Integration
#------------------------------------------------------------------------------

class TenetIDA(TenetCore):
    """
    The plugin integration layer IDA Pro.
    """

    def __init__(self):

        #
        # icons
        #

        self._icon_id_file = ida_idaapi.BADADDR
        self._icon_id_next_execution = ida_idaapi.BADADDR
        self._icon_id_prev_execution = ida_idaapi.BADADDR

        #
        # event hooks
        #

        self._hooked = False
        
        self._ui_hooks = UIHooks()
        self._ui_hooks.get_lines_rendering_info = self._render_lines
        self._ui_hooks.finish_populating_widget_popup = self._popup_hook

        self._dbg_hooks = DbgHooks()
        self._dbg_hooks.dbg_bpt_changed = self._breakpoint_changed_hook

        #
        # we should always hook the UI early in dev mode as we will use UI
        # events to auto-launch a trace
        #

        if is_plugin_dev():
            self._ui_hooks.hook()

        #
        # callbacks
        #

        self._ui_breakpoint_changed_callbacks = []

        #
        # run disassembler-agnostic core initalization
        #

        super(TenetIDA, self).__init__()

    def hook(self):
        if self._hooked:
            return
        self._hooked = True
        self._ui_hooks.hook()
        self._dbg_hooks.hook()

    def unhook(self):
        if not self._hooked:
            return
        self._hooked = False
        self._ui_hooks.unhook()
        self._dbg_hooks.unhook()

    def get_context(self, dctx, startup=True):
        """
        Get the plugin context for a given database.

        NOTE: since IDA can only have one binary / IDB open at a time, the
        dctx (database context) should always be IDA_GLOBAL_CTX.
        """
        assert dctx is IDA_GLOBAL_CTX
        self.palette.warmup()

        #
        # there should only ever be 'one' disassembler / IDB context at any
        # time for IDA. but if one does not exist yet, that means this is the
        # first time the user has interacted with the plugin for this session
        #

        if dctx not in self.contexts:

            # create a new 'plugin context' representing this IDB
            pctx = TenetContext(self, dctx)
            if startup:
                pctx.start()

            # save the created ctx for future calls
            self.contexts[dctx] = pctx

        # return the plugin context object for this IDB
        return self.contexts[dctx]

    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_LOAD_TRACE      = "tenet:load_trace"
    ACTION_FIRST_EXECUTION = "tenet:first_execution"
    ACTION_FINAL_EXECUTION = "tenet:final_execution"
    ACTION_NEXT_EXECUTION  = "tenet:next_execution"
    ACTION_PREV_EXECUTION  = "tenet:prev_execution"

    def _install_load_trace(self):

        # TODO: create a custom IDA icon 
        #icon_path = plugin_resource(os.path.join("icons", "load.png"))
        #icon_data = open(icon_path, "rb").read()
        #self._icon_id_file = ida_kernwin.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_LOAD_TRACE,                    # The action name
            "~T~enet trace file...",                   # The action text
            IDACtxEntry(self._interactive_load_trace), # The action handler
            None,                                      # Optional: action shortcut
            "Load a Tenet trace file",                 # Optional: tooltip
            -1                                         # Optional: the action icon
        )

        # register the action with IDA
        result = ida_kernwin.register_action(action_desc)
        assert result, f"Failed to register '{action_desc.name}' action with IDA"

        # attach the action to the File-> dropdown menu
        result = ida_kernwin.attach_action_to_menu(
            "File/Load file/",       # Relative path of where to add the action
            self.ACTION_LOAD_TRACE,  # The action ID (see above)
            ida_kernwin.SETMENU_APP  # We want to append the action after ^
        )
        assert result, f"Failed action attach {action_desc.name}"

        logger.info(f"Installed the '{action_desc.name}' menu entry")

    def _install_next_execution(self):

        icon_data = self.palette.gen_arrow_icon(self.palette.arrow_next, 0)
        self._icon_id_next_execution = ida_kernwin.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_NEXT_EXECUTION,                        # The action name
            "Go to next execution",                            # The action text
            IDACtxEntry(self._interactive_next_execution),     # The action handler
            None,                                              # Optional: action shortcut
            "Go to the next execution of the current address", # Optional: tooltip
            self._icon_id_next_execution                       # Optional: the action icon
        )

        # register the action with IDA
        result = ida_kernwin.register_action(action_desc)
        assert result, f"Failed to register '{action_desc.name}' action with IDA"
        logger.info(f"Installed the '{action_desc.name}' menu entry")

    def _install_prev_execution(self):

        icon_data = self.palette.gen_arrow_icon(self.palette.arrow_prev, 180.0)
        self._icon_id_prev_execution = ida_kernwin.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_PREV_EXECUTION,                            # The action name
            "Go to previous execution",                            # The action text
            IDACtxEntry(self._interactive_prev_execution),         # The action handler
            None,                                                  # Optional: action shortcut
            "Go to the previous execution of the current address", # Optional: tooltip
            self._icon_id_prev_execution                           # Optional: the action icon
        )

        # register the action with IDA
        result = ida_kernwin.register_action(action_desc)
        assert result, f"Failed to register '{action_desc.name}' action with IDA"
        logger.info(f"Installed the '{action_desc.name}' menu entry")

    def _install_first_execution(self):

        # describe a custom IDA UI action
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_FIRST_EXECUTION,                        # The action name
            "Go to first execution",                            # The action text
            IDACtxEntry(self._interactive_first_execution),     # The action handler
            None,                                               # Optional: action shortcut
            "Go to the first execution of the current address", # Optional: tooltip
            -1                                                  # Optional: the action icon
        )

        # register the action with IDA
        result = ida_kernwin.register_action(action_desc)
        assert result, f"Failed to register '{action_desc.name}' action with IDA"
        logger.info(f"Installed the '{action_desc.name}' menu entry")

    def _install_final_execution(self):

        # describe a custom IDA UI action
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_FINAL_EXECUTION,                        # The action name
            "Go to final execution",                            # The action text
            IDACtxEntry(self._interactive_final_execution),     # The action handler
            None,                                               # Optional: action shortcut
            "Go to the final execution of the current address", # Optional: tooltip
            -1                                                  # Optional: the action icon
        )

        # register the action with IDA
        result = ida_kernwin.register_action(action_desc)
        assert result, f"Failed to register '{action_desc.name}' action with IDA"
        logger.info(f"Installed the '{action_desc.name}' menu entry")

    def _uninstall_load_trace(self):

        logger.info("Removing the 'Tenet trace file...' menu entry...")

        # remove the entry from the File-> menu
        result = ida_kernwin.detach_action_from_menu(
            "File/Load file/",
            self.ACTION_LOAD_TRACE
        )
        if not result:
            logger.warning("Failed to detach action from menu...")
            return False

        # unregister the action
        result = ida_kernwin.unregister_action(self.ACTION_LOAD_TRACE)
        if not result:
            logger.warning("Failed to unregister action...")
            return False

        # delete the entry's icon
        #ida_kernwin.free_custom_icon(self._icon_id_file) # TODO
        self._icon_id_file = ida_idaapi.BADADDR

        logger.info("Successfully removed the menu entry!")
        return True

    def _uninstall_next_execution(self):
        result = self._uninstall_action(self.ACTION_NEXT_EXECUTION, self._icon_id_next_execution)
        self._icon_id_next_execution = ida_idaapi.BADADDR
        return result
        
    def _uninstall_prev_execution(self):
        result = self._uninstall_action(self.ACTION_PREV_EXECUTION, self._icon_id_prev_execution)
        self._icon_id_prev_execution = ida_idaapi.BADADDR
        return result
        
    def _uninstall_first_execution(self):
        return self._uninstall_action(self.ACTION_FIRST_EXECUTION)
        
    def _uninstall_final_execution(self):
        return self._uninstall_action(self.ACTION_FINAL_EXECUTION)

    def _uninstall_action(self, action, icon_id=ida_idaapi.BADADDR):

        result = ida_kernwin.unregister_action(action)
        if not result:
            logger.warning(f"Failed to unregister {action}...")
            return False

        if icon_id != ida_idaapi.BADADDR:
            ida_kernwin.free_custom_icon(icon_id)

        logger.info(f"Uninstalled the {action} menu entry")
        return True

    #--------------------------------------------------------------------------
    # UI Event Handlers
    #--------------------------------------------------------------------------

    def _breakpoint_changed_hook(self, code, bpt):
        """
        (Event) Breakpoint changed.
        """

        if code == ida_dbg.BPTEV_ADDED:
            self._notify_ui_breakpoint_changed(bpt.ea, BreakpointEvent.ADDED)

        elif code == ida_dbg.BPTEV_CHANGED:
            if bpt.enabled():
                self._notify_ui_breakpoint_changed(bpt.ea, BreakpointEvent.ENABLED)
            else:
                self._notify_ui_breakpoint_changed(bpt.ea, BreakpointEvent.DISABLED)

        elif code == ida_dbg.BPTEV_REMOVED:
            self._notify_ui_breakpoint_changed(bpt.ea, BreakpointEvent.REMOVED)

        return 0

    def _popup_hook(self, widget, popup):
        """
        (Event) IDA is about to show a popup for the given TWidget.
        """

        # TODO: return if plugin/trace is not active
        pass

        # fetch the (IDA) window type (eg, disas, graph, hex ...)
        view_type = ida_kernwin.get_widget_type(widget)

        # only attach these context items to popups in disas views
        if view_type == ida_kernwin.BWN_DISASMS:

            # prep for some shady hacks
            p_qmenu = ctypes.cast(int(popup), ctypes.POINTER(ctypes.c_void_p))[0]
            qmenu = sip.wrapinstance(int(p_qmenu), QtWidgets.QMenu)

            #
            # inject and organize the Tenet plugin actions
            #

            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                self.ACTION_NEXT_EXECUTION,  # The action ID (see above)
                "Rename",                    # Relative path of where to add the action
                ida_kernwin.SETMENU_APP      # We want to append the action after ^
            )

            #
            # this is part of our bodge to inject a plugin action submenu
            # at a specific location in the QMenu, cuz I don't think it's
            # actually possible with the native IDA API's (for groups...)
            #

            for action in qmenu.actions():
                if action.text() == "Go to next execution":

                    # inject a group for the exta 'go to' actions
                    goto_submenu = QtWidgets.QMenu("Go to...")
                    qmenu.insertMenu(action, goto_submenu)

                    # hold a Qt ref of the submenu so it doesn't GC
                    self.__goto_submenu = goto_submenu
                    break

            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                self.ACTION_FIRST_EXECUTION,     # The action ID (see above)
                "Go to.../",                     # Relative path of where to add the action
                ida_kernwin.SETMENU_APP          # We want to append the action after ^
            )

            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                self.ACTION_FINAL_EXECUTION,     # The action ID (see above)
                "Go to.../",                     # Relative path of where to add the action
                ida_kernwin.SETMENU_APP          # We want to append the action after ^
            )

            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                self.ACTION_PREV_EXECUTION,  # The action ID (see above)
                "Rename",                    # Relative path of where to add the action
                ida_kernwin.SETMENU_APP      # We want to append the action after ^
            )

            #
            # inject a seperator to help insulate our plugin action group
            #

            for action in qmenu.actions():
                if action.text() == "Go to previous execution":
                    qmenu.insertSeparator(action)
                    break

    def _render_lines(self, lines_out, widget, lines_in):
        """
        (Event) IDA is about to render code viewer lines.
        """
        widget_type = ida_kernwin.get_widget_type(widget)

        if widget_type == ida_kernwin.BWN_DISASM:
            self._highlight_disassesmbly(lines_out, widget, lines_in)

        return

    def _highlight_disassesmbly(self, lines_out, widget, lines_in):
        """
        TODO/XXX this is pretty gross
        """
        ctx = self.get_context(IDA_GLOBAL_CTX)
        if not ctx.reader:
            return
        
        trail_length = 6

        forward_color = self.palette.trail_forward
        current_color = self.palette.trail_current
        backward_color = self.palette.trail_backward

        r, g, b, _ = current_color.getRgb()
        current_color = 0xFF << 24 | b << 16 | g << 8 | r
        
        step_over = False
        modifiers = QtGui.QGuiApplication.keyboardModifiers()
        step_over = bool(modifiers & QtCore.Qt.ShiftModifier)
        #print("Stepping over?", step_over)

        forward_ips = ctx.reader.get_next_ips(trail_length, step_over)
        backward_ips = ctx.reader.get_prev_ips(trail_length, step_over)

        backward_trail, forward_trail = {}, {}

        trails = [
            (backward_ips, backward_trail, backward_color), 
            (forward_ips, forward_trail, forward_color)
        ]

        for addresses, trail, color in trails:
            for i, address in enumerate(addresses):
                percent = 1.0 - ((trail_length - i) / trail_length)

                # convert to bgr
                r, g, b, _ = color.getRgb()
                ida_color = b << 16 | g << 8 | r
                ida_color |= (0xFF - int(0xFF * percent)) << 24

                # save the trail color
                rebased_address = ctx.reader.analysis.rebase_pointer(address)
                trail[rebased_address] = ida_color

        current_address = ctx.reader.rebased_ip
        if not ida_bytes.is_mapped(current_address):
            last_good_idx = ctx.reader.analysis.get_prev_mapped_idx(ctx.reader.idx)
            if last_good_idx != -1:

                # fetch the last instruction pointer to fall within the trace
                last_good_trace_address = ctx.reader.get_ip(last_good_idx)

                # convert the trace-based instruction pointer to one that maps to the disassembler
                current_address = ctx.reader.analysis.rebase_pointer(last_good_trace_address)

        for section in lines_in.sections_lines:
            for line in section:
                address = line.at.toea()
                
                if address in backward_trail:
                    color = backward_trail[address]
                elif address in forward_trail:
                    color = forward_trail[address]
                elif address == current_address:
                    color = current_color
                else:
                    continue

                entry = ida_kernwin.line_rendering_output_entry_t(line, ida_kernwin.LROEF_FULL_LINE, color)
                lines_out.entries.push_back(entry)

    #----------------------------------------------------------------------
    # Callbacks
    #----------------------------------------------------------------------

    def ui_breakpoint_changed(self, callback):
        register_callback(self._ui_breakpoint_changed_callbacks, callback)

    def _notify_ui_breakpoint_changed(self, address, code):
        notify_callback(self._ui_breakpoint_changed_callbacks, address, code)

#------------------------------------------------------------------------------
# IDA UI Helpers
#------------------------------------------------------------------------------

class IDACtxEntry(ida_kernwin.action_handler_t):
    """
    A minimal context menu entry class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        super(IDACtxEntry, self).__init__()
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.

        NOTE: We pass 'None' to the action function to act as the '
        """
        self.action_function(IDA_GLOBAL_CTX)
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return ida_kernwin.AST_ENABLE_ALWAYS

#------------------------------------------------------------------------------
# IDA UI Event Hooks
#------------------------------------------------------------------------------

class DbgHooks(ida_dbg.DBG_Hooks):
    def dbg_bpt_changed(self, code, bpt):
        pass

class UIHooks(ida_kernwin.UI_Hooks):
    def get_lines_rendering_info(self, lines_out, widget, lines_in):
        pass
    def ready_to_run(self):
        pass
    def finish_populating_widget_popup(self, widget, popup):
        pass