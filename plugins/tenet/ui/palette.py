import os
import json
import shutil
import logging

from json.decoder import JSONDecodeError

from tenet.util.qt import *
from tenet.util.misc import *
from tenet.util.log import pmsg
from tenet.integration.api import disassembler

logger = logging.getLogger("Plugin.UI.Palette")

#------------------------------------------------------------------------------
# Plugin Color Palette
#------------------------------------------------------------------------------

class PluginPalette(object):
    """
    Theme palette for the plugin.
    """

    def __init__(self):
        """
        Initialize default palette colors for the plugin.
        """
        self._initialized = False
        self._last_directory = None
        self._required_fields = []

        # hints about the user theme (light/dark)
        self._user_qt_hint = "dark"
        self._user_disassembly_hint = "dark"

        self.theme = None
        self._default_themes = \
        {
            "dark":  "synth.json",
            "light": "horizon.json"
        }

        # list of objects requesting a callback after a theme change
        self._theme_changed_callbacks = []

        # get a list of required theme fields, for user theme validation
        self._load_required_fields()

        # initialize the user theme directory
        self._populate_user_theme_dir()

        # load a placeholder theme for inital Tenet bring-up
        self._load_default_theme()
        self._initialized = False

    @staticmethod
    def get_plugin_theme_dir():
        """
        Return the plugin theme directory.
        """
        return plugin_resource("themes")

    @staticmethod
    def get_user_theme_dir():
        """
        Return the user theme directory.
        """
        theme_directory = os.path.join(
            disassembler.get_disassembler_user_directory(),
            "tenet_themes"
        )
        return theme_directory

    #----------------------------------------------------------------------
    # Callbacks
    #----------------------------------------------------------------------

    def theme_changed(self, callback):
        """
        Subscribe a callback for theme change events.
        """
        register_callback(self._theme_changed_callbacks, callback)

    def _notify_theme_changed(self):
        """
        Notify listeners of a theme change event.
        """
        notify_callback(self._theme_changed_callbacks)

    #----------------------------------------------------------------------
    # Public
    #----------------------------------------------------------------------

    def warmup(self):
        """
        Warms up the theming system prior to initial use.
        """
        if self._initialized:
            return

        logger.debug("Warming up theme subsystem...")

        # attempt to load the user's preferred theme
        if self._load_preferred_theme():
            self._initialized = True
            logger.debug(" - warmup complete, using user theme!")
            return

        #
        # if no user selected theme is loaded, we will attempt to detect
        # and load the in-box themes based on the disassembler theme
        #

        if self._load_hinted_theme():
            logger.debug(" - warmup complete, using hint-recommended theme!")
            self._initialized = True
            return

        pmsg("Could not warmup theme subsystem!")

    def interactive_change_theme(self):
        """
        Open a file dialog and let the user select a new plugin theme.
        """

        # create & configure a Qt File Dialog for immediate use
        file_dialog = QtWidgets.QFileDialog(
            None,
            "Open plugin theme file",
            self._last_directory,
            "JSON Files (*.json)"
        )
        file_dialog.setFileMode(QtWidgets.QFileDialog.ExistingFile)

        # prompt the user with the file dialog, and await filename(s)
        filename, _ = file_dialog.getOpenFileName()
        if not filename:
            return

        #
        # ensure the user is only trying to load themes from the user theme
        # directory as it helps ensure some of our intenal loading logic
        #

        file_dir = os.path.abspath(os.path.dirname(filename))
        user_dir = os.path.abspath(self.get_user_theme_dir())
        if file_dir != user_dir:
            text = "Please install your plugin theme into the user theme directory:\n\n" + user_dir
            disassembler.warning(text)
            return

        #
        # remember the last directory we were in (parsed from a selected file)
        # for the next time the user comes to load a theme file
        #

        if filename:
            self._last_directory = os.path.dirname(filename) + os.sep

        # log the captured (selected) filenames from the dialog
        logger.debug("Captured filename from theme file dialog: '%s'" % filename)

        #
        # before applying the selected plugin theme, we should ensure that
        # we know if the user is using a light or dark disassembler theme as
        # it may change which colors get used by the plugin theme
        #

        self._refresh_theme_hints()

        # if the selected theme fails to load, throw a visible warning
        if not self._load_theme(filename):
            disassembler.warning(
                "Failed to load plugin user theme!\n\n"
                "Please check the console for more information..."
            )
            return

        # since everthing looks like it loaded okay, save this as the preferred theme
        with open(os.path.join(self.get_user_theme_dir(), ".active_theme"), "w") as f:
            f.write(filename)

    def refresh_theme(self):
        """
        Dynamically compute palette color based on the disassembler theme.

        Depending on if the disassembler is using a dark or light theme, we
        *try* to select colors that will hopefully keep things most readable.
        """
        if self._load_preferred_theme():
            return
        if self._load_hinted_theme():
            return
        pmsg("Failed to refresh theme!")

    def gen_arrow_icon(self, color, rotation):
        """
        Dynamically generate a colored/rotated arrow icon.
        """
        icon_path = plugin_resource(os.path.join("icons", "arrow.png"))

        img = QtGui.QPixmap(icon_path)

        if rotation:
            rm = QtGui.QTransform()
            rm.rotate(rotation)
            img = img.transformed(rm)

        mask = QtGui.QPixmap(img)

        p = QtGui.QPainter()
        p.begin(mask)
        p.setCompositionMode(QtGui.QPainter.CompositionMode_SourceIn)
        p.fillRect(img.rect(), color)
        p.end()

        p.begin(img)
        p.setCompositionMode(QtGui.QPainter.CompositionMode_Overlay)
        p.drawPixmap(0, 0, mask)
        p.end()

        # convert QPixmap to bytes
        ba = QtCore.QByteArray()
        buff = QtCore.QBuffer(ba)
        buff.open(QtCore.QIODevice.WriteOnly)
        ok = img.save(buff, "PNG", quality=100)
        assert ok

        return ba.data()

    #--------------------------------------------------------------------------
    # Theme Internals
    #--------------------------------------------------------------------------

    def _populate_user_theme_dir(self):
        """
        Create the plugin's user theme directory and install default themes.
        """

        # create the user theme directory if it does not exist
        user_theme_dir = self.get_user_theme_dir()
        makedirs(user_theme_dir)

        # copy the default themes into the user directory if they don't exist
        for theme_name in self._default_themes.values():

            #
            # check if the plugin has copied the default themes into the user
            # theme directory before. when 'default' themes exists, skip them
            # rather than overwriting... as the user may have modified it
            #

            user_theme_file = os.path.join(user_theme_dir, theme_name)
            if os.path.exists(user_theme_file):
                continue

            # copy the in-box themes to the user theme directory
            plugin_theme_file = os.path.join(self.get_plugin_theme_dir(), theme_name)
            shutil.copy(plugin_theme_file, user_theme_file)

        #
        # if the user tries to switch themes, ensure the file dialog will start
        # in their user theme directory
        #

        self._last_directory = user_theme_dir

    def _load_required_fields(self):
        """
        Load the required theme fields from a donor in-box theme.
        """
        logger.debug("Loading required theme fields from disk...")

        # load a known-good theme from the plugin's in-box themes
        filepath = os.path.join(self.get_plugin_theme_dir(), self._default_themes["dark"])
        theme = self._read_theme(filepath)

        #
        # save all the defined fields in this 'good' theme as a ground truth
        # to validate user themes against...
        #

        self._required_fields = theme["fields"].keys()

    def _load_default_theme(self):
        """
        Load the default theme without any sort of hinting.
        """
        theme_name = self._default_themes["dark"]
        theme_path = os.path.join(self.get_plugin_theme_dir(), theme_name)
        return self._load_theme(theme_path)

    def _load_hinted_theme(self):
        """
        Load the in-box plugin theme hinted at by the theme subsystem.
        """
        self._refresh_theme_hints()

        #
        # we have two themes hints which roughly correspond to the tone of
        # the user's disassembly background, and then the Qt subsystem.
        #
        # if both themes seem to align on style (eg the user is using a
        # 'dark' UI), then we will select the appropriate in-box theme
        #

        if self._user_qt_hint == self._user_disassembly_hint:
            theme_name = self._default_themes[self._user_qt_hint]
            logger.debug(" - No preferred theme, hints suggest theme '%s'" % theme_name)

        #
        # the UI hints don't match, so the user is using some ... weird
        # mismatched theming in their disassembler. let's just default to
        # the 'dark' plugin theme as it is more robust
        #

        else:
            theme_name = self._default_themes["dark"]

        # build the filepath to the hinted, in-box theme
        theme_path = os.path.join(self.get_plugin_theme_dir(), theme_name)

        # attempt to load and return the result of loading an in-box theme
        return self._load_theme(theme_path)

    def _load_preferred_theme(self):
        """
        Load the user's saved, preferred theme.
        """
        logger.debug("Loading preferred theme from disk...")
        user_theme_dir = self.get_user_theme_dir()

        # attempt te read the name of the user's active / preferred theme name
        active_filepath = os.path.join(user_theme_dir, ".active_theme")
        try:
            theme_name = open(active_filepath).read().strip()
            logger.debug(" - Got '%s' from .active_theme" % theme_name)
        except (OSError, IOError):
            return False

        # build the filepath to the user defined theme
        theme_path = os.path.join(self.get_user_theme_dir(), theme_name)

        # finally, attempt to load & apply the theme -- return True/False
        if self._load_theme(theme_path):
            return True

        #
        # failed to load the preferred theme... so delete the 'active'
        # file (if there is one) and warn the user before falling back
        #

        try:
            os.remove(os.path.join(self.get_user_theme_dir(), ".active_theme"))
        except:
            pass

        disassembler.warning(
            "Failed to load plugin user theme!\n\n"
            "Please check the console for more information..."
        )

        return False

    def _validate_theme(self, theme):
        """
        Pefrom rudimentary theme validation.
        """
        logger.debug(" - Validating theme fields for '%s'..." % theme["name"])
        user_fields = theme.get("fields", None)
        if not user_fields:
            pmsg("Could not find theme 'fields' definition")
            return False

        # check that all the 'required' fields exist in the given theme
        for field in self._required_fields:
            if field not in user_fields:
                pmsg("Could not find required theme field '%s'" % field)
                return False

        # theme looks good enough for now...
        return True

    def _load_theme(self, filepath):
        """
        Load and apply the plugin theme at the given filepath.
        """

        # attempt to read json theme from disk
        try:
            theme = self._read_theme(filepath)

        # reading file from dsik failed
        except OSError:
            pmsg("Could not open theme file at '%s'" % filepath)
            return False

        # JSON decoding failed
        except JSONDecodeError as e:
            pmsg("Failed to decode theme '%s' to json" % filepath)
            pmsg(" - " + str(e))
            return False

        # do some basic sanity checking on the given theme file
        if not self._validate_theme(theme):
            pmsg("Failed to validate theme '%s'" % filepath)
            return False

        # try applying the loaded theme to the plugin
        try:
            self._apply_theme(theme)
        except Exception as e:
            pmsg("Failed to load the plugin user theme\n%s" % e)
            return False

        # return success
        self._notify_theme_changed()
        return True

    def _read_theme(self, filepath):
        """
        Parse the plugin theme file from the given filepath.
        """
        logger.debug(" - Reading theme file '%s'..." % filepath)

        # attempt to load the theme file contents from disk
        raw_theme = open(filepath, "r").read()

        # convert the theme file contents to a json object/dict
        theme = json.loads(raw_theme)

        # all good
        return theme

    def _apply_theme(self, theme):
        """
        Apply the given theme definition to the plugin.
        """
        logger.debug(" - Applying theme '%s'..." % theme["name"])
        colors = theme["colors"]

        for field_name, color_entry in theme["fields"].items():

            # color has 'light' and 'dark' variants
            if isinstance(color_entry, list):
                color_name = self._pick_best_color(field_name, color_entry)

            # there is only one color defined
            else:
                color_name = color_entry

            # load the color
            color_value = colors[color_name]
            color = QtGui.QColor(*color_value)

            # set theme self.[field_name] = color
            setattr(self, field_name, color)

        # all done, save the theme in case we need it later
        self.theme = theme

    def _pick_best_color(self, field_name, color_entry):
        """
        Given a variable color_entry, select the best color based on the theme hints.

        TODO: Most of this file is ripped from Lighthouse, including this func. In
        Lighthouse is behaves a bit different than it does here, but I'm too lazy
        to refactor/remove it for now (and maybe it'll get used later on??)
        """
        assert len(color_entry) == 2, "Malformed color entry, must be (dark, light)"
        dark, light = color_entry

        if self._user_qt_hint == "dark":
            return dark

        return light

    #--------------------------------------------------------------------------
    # Theme Inference
    #--------------------------------------------------------------------------

    def _refresh_theme_hints(self):
        """
        Peek at the UI context to infer what kind of theme the user might be using.
        """
        self._user_qt_hint = self._qt_theme_hint()
        self._user_disassembly_hint = self._disassembly_theme_hint() or "dark"

    def _disassembly_theme_hint(self):
        """
        Binary hint of the disassembler color theme.

        This routine returns a best effort hint as to what kind of theme is
        in use for the IDA Views (Disas, Hex, HexRays, etc).

        Returns 'dark' or 'light' indicating the user's theme
        """

        #
        # determine whether to use a 'dark' or 'light' paint based on the
        # background color of the user's disassembly text based windows
        #

        bg_color = disassembler.get_disassembly_background_color()
        if not bg_color:
            logger.debug(" - Failed to get hint for disassembly background...")
            return None

        # return 'dark' or 'light'
        return test_color_brightness(bg_color)

    def _qt_theme_hint(self):
        """
        Binary hint of the Qt color theme.

        This routine returns a best effort hint as to what kind of theme the
        QtWdigets throughout IDA are using. This is to accomodate for users
        who may be using Zyantific's IDASkins plugins (or others) to further
        customize IDA's appearance.

        Returns 'dark' or 'light' indicating the user's theme
        """

        #
        # to determine what kind of Qt based theme IDA is using, we create a
        # test widget and check the colors put into the palette the widget
        # inherits from the application (eg, IDA).
        #

        test_widget = QtWidgets.QWidget()

        #
        # in order to 'realize' the palette used to render (draw) the widget,
        # it first must be made visible. since we don't want to be popping
        # random widgets infront of the user, so we set this attribute such
        # that we can silently bake the widget colors.
        #
        # NOTE/COMPAT: WA_DontShowOnScreen
        #
        #   https://www.riverbankcomputing.com/news/pyqt-56
        #
        #   lmao, don't ask me why they forgot about this attribute from 5.0 - 5.6
        #

        if disassembler.NAME == "BINJA":
            test_widget.setAttribute(QtCore.Qt.WA_DontShowOnScreen)
        else:
            test_widget.setAttribute(103) # taken from http://doc.qt.io/qt-5/qt.html

        # render the (invisible) widget
        test_widget.show()

        # now we farm the background color from the qwidget
        bg_color = test_widget.palette().color(QtGui.QPalette.Window)

        # 'hide' & delete the widget
        test_widget.hide()
        test_widget.deleteLater()

        # return 'dark' or 'light'
        return test_color_brightness(bg_color)

#-----------------------------------------------------------------------------
# Palette Util
#-----------------------------------------------------------------------------

def test_color_brightness(color):
    """
    Test the brightness of a color.
    """
    if color.lightness() > 255.0/2:
        return "light"
    else:
        return "dark"
