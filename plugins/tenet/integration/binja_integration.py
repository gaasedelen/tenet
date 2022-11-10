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