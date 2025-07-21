import time
import logging

import ida_idaapi
import ida_kernwin

from tenet.util.log import pmsg
from tenet.integration.ida_integration import TenetIDA

logger = logging.getLogger("Tenet.IDA.Loader")

#------------------------------------------------------------------------------
# IDA Plugin Loader
#------------------------------------------------------------------------------
#
#    This file contains a stub 'plugin' class for the plugin as required by
#    IDA Pro. Practically speaking, there should be little to *no* logic placed
#    in this file because it is disassembler-specific.
#
#    When IDA Pro is starting up, it will import all python files placed in its
#    root plugin folder. It will then attempt to call PLUGIN_ENTRY() on each of
#    the imported 'plugins'. We import PLUGIN_ENTRY into tenet_plugin.py
#    so that IDA can see it.
#
#    PLUGIN_ENTRY() is expected to return a plugin object (TenetIDAPlugin)
#    derived from ida_idaapi.plugin_t. IDA will register the plugin, and
#    interface with the plugin object to load / unload the plugin at certain
#    times, per its configuration (flags, hotkeys).
#
#    There should be virtually no reason for you to modify this file.
#

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return TenetIDAPlugin()

class TenetIDAPlugin(ida_idaapi.plugin_t):
    """
    The IDA plugin stub for Tenet.
    """

    #
    # Plugin flags:
    # - PLUGIN_MOD:  The plugin may modify the database
    # - PLUGIN_PROC: Load/unload the plugin when an IDB opens / closes
    # - PLUGIN_HIDE: Hide the plugin from the IDA plugin menu
    #

    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_MOD | ida_idaapi.PLUGIN_HIDE
    comment = "Trace Explorer"
    help = ""
    wanted_name = "Tenet"
    wanted_hotkey = ""

    #--------------------------------------------------------------------------
    # IDA Plugin Overloads
    #--------------------------------------------------------------------------

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """

        try:
            self.core = TenetIDA()
            self.core.load()
        except Exception as e:
            pmsg("Failed to initialize Tenet")
            logger.exception("Exception details:")

        #
        # we return PLUGIN_KEEP here regardless of success/failure. this is to
        # ensure that IDA will not try to reload the plugin again.
        #

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        ida_kernwin.warning("Tenet cannot be run as a script in IDA.")

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """
        logger.debug("IDA term started...")

        start = time.time()
        logger.debug("-"*50)

        try:
            self.core.unload()
            self.core = None
        except Exception as e:
            logger.exception("Failed to cleanly unload Tenet from IDA.")

        end = time.time()
        logger.debug("-"*50)

        logger.debug("IDA term done... (%.3f seconds...)" % (end-start))

