from tenet.util.qt import QT_AVAILABLE

# import Qt based plugin UI if available
if QT_AVAILABLE:
    from tenet.ui.palette import PluginPalette
    from tenet.ui.hex_view import HexView
    from tenet.ui.reg_view import RegisterView
    from tenet.ui.breakpoint_view import BreakpointView
