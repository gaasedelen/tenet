import abc
import logging

from tenet.util.log import pmsg
from tenet.ui.palette import PluginPalette
from tenet.util.update import check_for_update
from tenet.integration.api import disassembler

logger = logging.getLogger("Tenet.Core")

#------------------------------------------------------------------------------
# core.py -- Plugin Core
#------------------------------------------------------------------------------
#
#    The purpose of this file is to define a specification required by the
#    plugin to integrate and load under a given disassembler.
#
#    This is technically the 'lowest' level layer of the plugin, as it is
#    loaded / unloaded directly by the disassembler. This means that there
#    should be no database or user-specific data loaded into this layer.
# 
#    Supporting additional disassemblers will require one to subclass this
#    abstract core as part of a disassembler-specific integration layer.
#

class TenetCore(object):
    """
    The disassembler-wide plugin core.
    """
    __metaclass__ = abc.ABCMeta

    #--------------------------------------------------------------------------
    # Plugin Metadata
    #--------------------------------------------------------------------------

    PLUGIN_NAME    = "Tenet"
    PLUGIN_VERSION = "0.2.0"
    PLUGIN_AUTHORS = "Markus Gaasedelen"
    PLUGIN_DATE    = "2021"

    #--------------------------------------------------------------------------
    # Initialization / Teardown
    #--------------------------------------------------------------------------

    def load(self):
        """
        Load the plugin, and register universal UI actions with the disassembler.
        """
        self.contexts = {}
        self._update_checked = False

        # the plugin color palette
        self.palette = PluginPalette()
        self.palette.theme_changed(self.refresh_theme)

        # integrate plugin UI to disassembler
        self._install_ui()

        # all done, mark the core as loaded
        self.loaded = True
        
        # print plugin banner
        pmsg(f"Loaded v{self.PLUGIN_VERSION} - (c) {self.PLUGIN_AUTHORS} - {self.PLUGIN_DATE}")
        logger.info("Successfully loaded plugin")

    def unload(self):
        """
        Unload the plugin, and remove any UI integrations.
        """
        if not self.loaded:
            return

        pmsg("Unloading %s..." % self.PLUGIN_NAME)

        # mark the core as 'unloaded' and teardown its components
        self.loaded = False

        # remove UI integrations
        self._uninstall_ui()

        # spin down any active contexts (stop threads, cleanup qt state, etc)
        for pctx in self.contexts.values():
            pctx.terminate()
        self.contexts = {}

        # all done
        logger.info("-"*75)
        logger.info("Plugin terminated")

    @abc.abstractmethod
    def hook(self):
        """
        Install disassmbler-specific hooks.
        """
        pass

    @abc.abstractmethod
    def unhook(self):
        """
        Remove disassmbler-specific hooks.
        """
        pass

    #--------------------------------------------------------------------------
    # Disassembler / Database Context Selector
    #--------------------------------------------------------------------------

    @abc.abstractmethod
    def get_context(self, db, startup=True):
        """
        Get the plugin context object for the given database / session.
        """
        pass

    #--------------------------------------------------------------------------
    # UI Integration
    #--------------------------------------------------------------------------

    def _install_ui(self):
        """
        Initialize & integrate all plugin UI elements.
        """
        self._install_load_trace()
        self._install_next_execution()
        self._install_prev_execution()
        self._install_first_execution()
        self._install_final_execution()

    def _uninstall_ui(self):
        """
        Cleanup & remove all plugin UI integrations.
        """
        self._uninstall_load_trace()
        self._uninstall_next_execution()
        self._uninstall_prev_execution()
        self._uninstall_first_execution()
        self._uninstall_final_execution()

    @abc.abstractmethod
    def _install_load_trace(self):
        """
        Install the 'File->Load->Tenet trace file...' menu entry.
        """
        pass

    @abc.abstractmethod
    def _install_next_execution(self):
        """
        Install the right click 'Go to next execution' menu entry.
        """
        pass

    @abc.abstractmethod
    def _install_prev_execution(self):
        """
        Install the right click 'Go to previous execution' menu entry.
        """
        pass

    @abc.abstractmethod
    def _install_first_execution(self):
        """
        Install the right click 'Go to first execution' menu entry.
        """
        pass

    @abc.abstractmethod
    def _install_final_execution(self):
        """
        Install the right click 'Go to final execution' menu entry.
        """
        pass

    @abc.abstractmethod
    def _uninstall_load_trace(self):
        """
        Remove the 'File->Load file->Tenet trace file...' menu entry.
        """
        pass

    @abc.abstractmethod
    def _uninstall_next_execution(self):
        """
        Remove the right click 'Go to next execution' menu entry.
        """
        pass

    @abc.abstractmethod
    def _uninstall_prev_execution(self):
        """
        Remove the right click 'Go to previous execution' menu entry.
        """
        pass

    @abc.abstractmethod
    def _uninstall_first_execution(self):
        """
        Remove the right click 'Go to first execution' menu entry.
        """
        pass

    @abc.abstractmethod
    def _uninstall_final_execution(self):
        """
        Remove the right click 'Go to final execution' menu entry.
        """
        pass

    #--------------------------------------------------------------------------
    # UI Event Handlers
    #--------------------------------------------------------------------------

    def _interactive_load_trace(self, db):
        pctx = self.get_context(db)
        pctx.interactive_load_trace()

    def _interactive_first_execution(self, db):
        pctx = self.get_context(db)
        pctx.interactive_first_execution()

    def _interactive_final_execution(self, db):
        pctx = self.get_context(db)
        pctx.interactive_final_execution()

    def _interactive_next_execution(self, db):
        pctx = self.get_context(db)
        pctx.interactive_next_execution()

    def _interactive_prev_execution(self, db):
        pctx = self.get_context(db)
        pctx.interactive_prev_execution()

    #--------------------------------------------------------------------------
    # Core Actions
    #--------------------------------------------------------------------------

    def refresh_theme(self):
        """
        Refresh UI facing elements to reflect the current theme.
        """
        for pctx in self.contexts.values():
            pass # TODO

    def check_for_update(self):
        """
        Check if there is an update available for the plugin.
        """
        if self._update_checked:
            return

        # wrap the callback (a popup) to ensure it gets called from the UI
        callback = disassembler.execute_ui(disassembler.warning)

        # kick off the async update check
        check_for_update(self.PLUGIN_VERSION, callback)
        self._update_checked = True
