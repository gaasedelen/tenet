#
# TODO: BIG DISCLAIMER -- The trace visualization / window does *not* make
# use of the MVC pattern that the other widgets do.
# 
# this is mainly due to the fact that it was prototyped last, and I haven't
# gotten around to moving the 'logic' out of window/widget classes and into
# a dedicated controller class.
#
# this will probably happen sooner than later, to keep everything consistent
#

from tenet.types import BreakpointType
from tenet.util.qt import *
from tenet.util.misc import register_callback, notify_callback

#------------------------------------------------------------------------------
# TraceView
#------------------------------------------------------------------------------

# TODO/XXX: ugly
BORDER_SIZE = 1
LOCKON_DISTANCE = 4

class TraceBar(QtWidgets.QWidget):
    """
    A trace visualization.
    """

    def __init__(self, core, zoom=False, parent=None):
        super(TraceBar, self).__init__(parent)
        self.core = core
        self._is_zoom = zoom

        # misc widget settings
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        self.setMouseTracking(True)
        self.setMinimumSize(32, 32)

        # the rendered trace visualization
        self._image = QtGui.QImage()

        #
        # setup trace colors / pens / brushes
        #

        # r / w / x accesses
        self.color_read = self.core.palette.mem_read_bg
        self.color_write = self.core.palette.mem_write_bg
        self.color_exec = self.core.palette.breakpoint

        # current idx
        self.color_cursor = self.core.palette.trace_cursor
        self.cursor_pen = QtGui.QPen(self.color_cursor, 1, QtCore.Qt.SolidLine)

        # zoom / region selection
        self.color_selection = self.core.palette.trace_selection
        self.color_selection_border = self.core.palette.trace_selection_border
        self.pen_selection = QtGui.QPen(self.color_selection, 2, QtCore.Qt.SolidLine)
        self.brush_selection = QtGui.QBrush(QtCore.Qt.Dense6Pattern)
        self.brush_selection.setColor(self.color_selection_border)

        self._last_hovered = None

        self.start_idx = 0
        self.end_idx = 0
        self.density = 0

        self._width = 0
        self._height = 0

        self._selection_origin = -1
        self._selection_start = -1
        self._selection_end = -1

        self._executions = []
        self._reads = []
        self._writes = []

        #----------------------------------------------------------------------
        # Callbacks
        #----------------------------------------------------------------------

        self._selection_changed_callbacks = []

    def _focused_breakpoint_changed(self, breakpoint):
        """
        The focused breakpoint has changed.
        """
        self._refresh_breakpoint_hits(breakpoint)
        self.refresh()

    def _refresh_breakpoint_hits(self, breakpoint):
        self._executions = []
        self._reads = []
        self._writes = []
        
        if not self.isVisible():
            return

        if not (self.core.reader and breakpoint):
            return

        if breakpoint.type == BreakpointType.EXEC:
            
            self._executions = self.core.reader.get_executions_between(breakpoint.address, self.start_idx, self.end_idx, self.density)

        elif breakpoint.type == BreakpointType.ACCESS:

            if breakpoint.length == 1:
                self._reads, self._writes = self.core.reader.get_memory_accesses_between(breakpoint.address, self.start_idx, self.end_idx, self.density)
            else:
                self._reads, self._writes = self.core.reader.get_memory_region_accesses_between(breakpoint.address, breakpoint.length, self.start_idx, self.end_idx, self.density)

        else:
            raise NotImplementedError

    def attach_reader(self, reader):

        # clear out any existing state
        self.reset()

        # save the reader
        self.reader = reader

        # initialize state based on the reader
        self.set_zoom(0, reader.trace.length)

        # attach signals to the new reader
        reader.idx_changed(self.refresh)

    def reset(self):
        """
        TODO
        """
        self.reader = None
        
        self.start_idx = 0
        self.end_idx = 0
        self.density = 0

        self._selection_origin = -1
        self._selection_start = -1
        self._selection_end = -1

        self._executions = []
        self._reads = []
        self._writes = []

        self.refresh()

    def refresh(self, *args):
        """
        TODO
        """
        self._draw_trace()
        self.update()

    def _idx2pos(self, idx):
        """
        Translate a given Y coordinate to an approximate IDX.
        """
        relative_idx = idx - self.start_idx
        y = int(relative_idx / self.density) + BORDER_SIZE
        
        if y < BORDER_SIZE:
            y = BORDER_SIZE

        elif y > (self._height - BORDER_SIZE):
            y = self._height

        return y

    def _pos2idx(self, y):
        """
        Translate a given Y coordinate to an approximate IDX.
        """
        y -= BORDER_SIZE

        relative_idx = round(y * self.density)
        idx = self.start_idx + relative_idx

        # clamp IDX to the start / end of the trace
        if idx < self.start_idx:
            idx = self.start_idx
        elif idx > self.end_idx:
            idx = self.end_idx

        return idx

    def _compute_pixel_distance(self, y, idx):
        """
        Compute the pixel distance from a given y to an IDX.
        """
        y_idx = ((idx - self.start_idx) / self.density) - BORDER_SIZE
        distance_pixels = abs(y-y_idx)
        return distance_pixels

    def _update_hover(self, current_y):
        """
        TODO
        """

        # fast path / nothing to do if hovered position hasn't changed
        if self._last_hovered and self._last_hovered[1] == current_y:
            return

        # see if there's an interesting trace event close to the hover
        hovered_idx = self._pos2idx(current_y)
        closest_idx = self._get_closest_visible_idx(hovered_idx)
        px_distance = self._compute_pixel_distance(current_y, closest_idx)

        #print(f" HOVERED IDX {hovered_idx:,}, CLOSEST IDX {closest_idx:,}, DIST {px_distance}")

        painter = QtGui.QPainter(self._image)
        LINE_WIDTH = self._width - (BORDER_SIZE * 2)

        # unpaint the last hovered line with the position/color we stored for it
        if self._last_hovered:
            old_data, prev_y = self._last_hovered
            length = min(len(old_data), self._image.width() * 4)
            current_data = self._image.scanLine(prev_y).asarray(length)
            for i in range(length):
                current_data[i] = old_data[i]

        # nothing close, so don't bother painting a highlight
        if px_distance >= LOCKON_DISTANCE:
            self._last_hovered = None
            #print("NOTHING CLOSE!")
            self._draw_cursor(painter)
            return

        locked_y = self._idx2pos(closest_idx)

        # overwrite last_hovered with the latest hover position / color we will stomp
        current_line_data = self._image.scanLine(locked_y)
        old_data = [x for x in current_line_data.asarray(4 * self._image.width())]
        self._last_hovered = (old_data, locked_y)
        #self._last_hovered = (self._image.pixelColor(LINE_WIDTH//2, locked_y), locked_y)
        
        # paint the currently hovered line
        painter.setPen(self.cursor_pen)
        painter.drawLine(BORDER_SIZE, locked_y, LINE_WIDTH, locked_y)
        #print("PAINTED NEW!")

        self._draw_cursor(painter)

    def set_zoom(self, start_idx, end_idx):
        """
        TODO
        """
        #print("Setting Zoom!", start_idx, end_idx)

        # save the first and last timestamps to be shown
        self.start_idx = start_idx
        self.end_idx = end_idx

        # compute the number of instructions visible
        self.length = (end_idx - start_idx)

        # compute the number of instructions per y pixel
        self.density = self.length / (self._height - BORDER_SIZE * 2) 

        self._refresh_breakpoint_hits(self.core.breakpoints.model.focused_breakpoint)
        self.refresh()

    def set_selection(self, start_idx, end_idx):
        """
        TODO
        """
        self._selection_end = end_idx
        self._selection_start = start_idx
        self.refresh()

    def _global_selection_changed(self, start_idx, end_idx):
        if start_idx == end_idx:
            return
        self.set_selection(start_idx, end_idx)
        
    def _zoom_selection_changed(self, start_idx, end_idx):
        if start_idx == end_idx:
            self.hide()
        else:
            self.show()
            self.set_zoom(start_idx, end_idx)

    def highlight_executions(self, idxs):
        self._executions = idxs
        self.refresh()

    def _draw_trace(self):
        w, h = self._width, self._height
        self._last_hovered = None

        self._image = QtGui.QImage(w, h, QtGui.QImage.Format_RGB32)
        
        if not self.reader:
           self._image.fill(self.core.palette.trace_bedrock)
        else:
           self._image.fill(self.core.palette.trace_instruction)

        painter = QtGui.QPainter(self._image)

        #
        # draw accesses along the trace timeline
        #

        self._draw_accesses(painter)
                
        #
        # draw region selection 
        #
        
        self._draw_selection(painter)
        
        #
        # draw border around trace timeline
        #

        border_pen = QtGui.QPen(self.core.palette.trace_border, 1, QtCore.Qt.SolidLine)
        painter.setPen(border_pen)

        # top & bottom
        painter.drawLine(0, 0, w, 0)
        painter.drawLine(0, h-1, w, h-1)

        # left & right
        painter.drawLine(0, 0, 0, h)
        painter.drawLine(w-1, 0, w-1, h)

        # 
        # draw current trace position cursor
        #

        self._draw_cursor(painter)

    def _draw_accesses(self, painter):
        """
        Draw read / write / execs accesses on the trace timeline.
        """

        access_sets = \
        [
            (self._reads, self.color_read),
            (self._writes, self.color_write),
            (self._executions, self.color_exec),
        ]

        for entries, color in access_sets:
            painter.setPen(color)

            for idx in entries:
                
                # skip entries that fall outside the visible zoom
                if not(self.start_idx <= idx < self.end_idx):
                    continue
                
                relative_idx = idx - self.start_idx
                y = int(relative_idx / self.density) + BORDER_SIZE
                painter.drawLine(0, y, self._width, y)

    def _draw_cursor(self, painter):
        """
        Draw the user cursor / current position in the trace.
        """
        if not self.reader:
            return

        path = QtGui.QPainterPath()
        
        size = 13
        assert size % 2, "Cursor triangle size must be odd"

        # rebase the absolute trace cursor idx to the current 'zoomed' view
        relative_idx = self.reader.idx - self.start_idx
        if relative_idx < 0:
            return False

        # compute the y coordinate / line to center the user cursor around
        cursor_y = int(relative_idx / self.density) + BORDER_SIZE

        # the top point of the triangle
        top_x = 0
        top_y = cursor_y - (size // 2) # vertically align the triangle so the tip matches the cross section
        #print("TOP", top_x, top_y)
        
        # bottom point of the triangle
        bottom_x = top_x
        bottom_y = top_y + size - 1
        #print("BOT", bottom_x, bottom_y)

        # the 'tip' of the triangle pointing into towards the center of the trace
        tip_x = top_x + (size // 2)
        tip_y = top_y + (size // 2)
        #print("CURSOR", tip_x, tip_y)

        # start drawing from the 'top' of the triangle
        path.moveTo(top_x, top_y)
        
        # generate the triangle path / shape
        path.lineTo(bottom_x, bottom_y)
        path.lineTo(tip_x, tip_y)
        path.lineTo(top_x, top_y)

        painter.setPen(self.cursor_pen)
        painter.drawLine(0, cursor_y, self._width, cursor_y)
        
        # paint the defined triangle
        # TODO: don't hardcode colors
        painter.setPen(QtCore.Qt.black)
        painter.setBrush(QtGui.QBrush(QtGui.QColor("red")))
        painter.drawPath(path)

    def _draw_selection(self, painter):
        """
        Draw a region selection rect.
        """
        #print("DRAWING SELECTION?", self._selection_start, self._selection_end)
        if self._selection_start == self._selection_end:
            return

        start_y = int((self._selection_start - self.start_idx) / self.density)
        end_y = int((self._selection_end - self.start_idx) / self.density)

        painter.setBrush(self.brush_selection)
        painter.setPen(self.pen_selection)
        painter.drawRect(
            BORDER_SIZE,                            # x
            start_y+BORDER_SIZE,                    # y
            self._width - (BORDER_SIZE * 2),        # width
            end_y - start_y - (BORDER_SIZE * 2)     # height
        )

    def wheelEvent(self, event):

        if not self.reader:
            return
            
        mod = QtGui.QGuiApplication.keyboardModifiers()
        step_over = bool(mod & QtCore.Qt.ShiftModifier)

        if event.angleDelta().y() > 0:
            self.reader.step_backward(1, step_over)

        elif event.angleDelta().y() < 0:
            self.reader.step_forward(1, step_over)

        self.refresh()
        event.accept()

    def _update_selection(self, y):
        idx_event = self._pos2idx(y)

        if idx_event > self._selection_origin:
            self._selection_start = self._selection_origin
            self._selection_end = idx_event
        else:
            self._selection_end = self._selection_origin
            self._selection_start = idx_event

    def mouseMoveEvent(self, event):
        #mod = QtGui.QGuiApplication.keyboardModifiers()
        #if mod & QtCore.Qt.ShiftModifier:
        #    print("SHIFT IS HELD!!")
        #import ida_kernwin
        #ida_kernwin.refresh_idaview_anyway()
        if event.buttons() == QtCore.Qt.MouseButton.LeftButton:
            self._update_selection(event.y())
            self.refresh()
        else:
            self._update_hover(event.y())
            self.update()

    def mousePressEvent(self, event):
        """
        Qt override to capture mouse button presses
        """

        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            idx_origin = self._pos2idx(event.y())
            self._selection_origin = idx_origin
            self._selection_start = idx_origin
            self._selection_end = idx_origin
            
        return

    def _get_closest_visible_idx(self, idx):
        """
        Return the closest IDX (timestamp) to the given IDX.
        """
        closest_idx = -1
        smallest_distace = 999999999999999999999999
        for entries in [self._reads, self._writes, self._executions]:
            for current_idx in entries:
                distance = abs(idx - current_idx)
                if distance < smallest_distace:
                    closest_idx = current_idx
                    smallest_distace = distance
        return closest_idx

    #overridden event to capture mouse button releases
    def mouseReleaseEvent(self, event):
        if not self.reader:
            return

        # if the left mouse button was released...
        if event.button() == QtCore.Qt.MouseButton.LeftButton:

            #
            # the initial 'click' origin is not set, so that means the 'click'
            # event did not start over this widget... or is something we
            # should just ignore.
            #

            if self._selection_origin == -1:
                return

            #
            # clear the selection origin as we will be consuming the
            # selection event in the followin codepath
            #

            self._selection_origin = -1

            #
            # if the user selection appears to be a 'click' vs a zoom / range
            # selection, then seek to the clicked address
            #

            if self._selection_start == self._selection_end:
                selected_idx = self._selection_start
                #clear_focus = True

                #
                # if there is a highlighted bp near the click, we should lock
                # onto that instead...
                #

                closest_idx = self._get_closest_visible_idx(selected_idx)
                current_y = self._idx2pos(self._selection_start)
                px_distance = self._compute_pixel_distance(current_y, closest_idx)
                if px_distance < LOCKON_DISTANCE:
                    selected_idx = closest_idx
                #    clear_focus = False
                #elif self._is_zoom:
                #    clear_focus = False

                #
                # jump to the selected area
                #

                #print(f"Jumping to {selected_idx:,}")
                self.reader.seek(selected_idx)
                #if clear_focus:
                #    self.core.breakpoints.model.focused_breakpoint = None

                self._notify_selection_changed(selected_idx, selected_idx)
                self.refresh()
                return

            if self._is_zoom:
                new_start = self._selection_start
                new_end = self._selection_end
                self._selection_start = self._selection_end = -1
                self.set_zoom(new_start, new_end)
                self._notify_selection_changed(new_start, new_end)
            else:
                self._notify_selection_changed(self._selection_start, self._selection_end)

    def leaveEvent(self, event):
        self.refresh()

    def keyPressEvent(self, e):
        #print("PRESSING", e.key(), e.modifiers())
        pass

    def keyReleaseEvent(self, e):
        #print("RELEASING", e.key(), e.modifiers())
        pass

    def resizeEvent(self, event):
        size = event.size()
        self._width, self._height = self.width(), self.height()
        self.density = self.length / (self._height - BORDER_SIZE * 2) 
        #self._refresh_breakpoint_hits(breakpoint)
        self.refresh()

    def paintEvent(self, event):
        painter = QtGui.QPainter(self)
        painter.drawImage(0, 0, self._image)

    #----------------------------------------------------------------------
    # Callbacks
    #----------------------------------------------------------------------

    def selection_changed(self, callback):
        """
        Subscribe a callback for a trace slice selection change event.
        """
        register_callback(self._selection_changed_callbacks, callback)

    def _notify_selection_changed(self, start_idx, end_idx):
        """
        Notify listeners of a trace slice selection change event.
        """
        notify_callback(self._selection_changed_callbacks, start_idx, end_idx)

class TraceView(QtWidgets.QWidget):
    def __init__(self, core, parent=None):
        super(TraceView, self).__init__(parent)
        self.core = core
        self._init_ui()

    def _init_ui(self):
        """
        TODO
        """
        self._init_bars()
        self._init_ctx_menu()

    def attach_reader(self, reader):
        self.trace_global.attach_reader(reader)
        self.trace_local.attach_reader(reader)
        self.trace_local.hide()

    def detach_reader(self):
        self.trace_global.reset() 
        self.trace_local.reset() 
        self.trace_local.hide()

    def _init_bars(self):
        """
        TODO
        """
        self.trace_local = TraceBar(self.core, zoom=True)
        self.trace_global = TraceBar(self.core)

        # connect the local view to follow the global selection
        self.trace_global.selection_changed(self.trace_local._zoom_selection_changed)
        self.trace_local.selection_changed(self.trace_global._global_selection_changed)

        # connect other signals 
        self.core.breakpoints.model.focused_breakpoint_changed(self.trace_global._focused_breakpoint_changed)
        self.core.breakpoints.model.focused_breakpoint_changed(self.trace_local._focused_breakpoint_changed)

        # hide the zoom bar by default
        self.trace_local.hide()
        
        # setup the layout and spacing for the tracebar
        hbox = QtWidgets.QHBoxLayout(self)
        hbox.setContentsMargins(3, 3, 3, 3)
        hbox.setSpacing(3)

        # add the layout container / mechanism to the toolbar
        hbox.addWidget(self.trace_local)
        hbox.addWidget(self.trace_global)

        self.setLayout(hbox)

    def _init_ctx_menu(self):
        """
        TODO
        """
        self._menu = QtWidgets.QMenu()

        # create actions to show in the context menu
        self._action_load = self._menu.addAction("Load new trace")
        self._action_close = self._menu.addAction("Close trace")

        # install the right click context menu
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._ctx_menu_handler)

    #--------------------------------------------------------------------------
    # Signals
    #--------------------------------------------------------------------------

    def _ctx_menu_handler(self, position):
        action = self._menu.exec_(self.mapToGlobal(position))
        if action == self._action_load:
            self.core.interactive_load_trace(True)
        elif action == self._action_close:
            self.core.close_trace()

    # if a tracebar got added, we need to update the layout
    def update_from_model(self):
        for bar in self.model.tracebars.values()[::-1]:
            self.hbox.addWidget(bar)

        # this will insert the children (tracebars) and apply spacing as appropriate
        self.bar_container.setLayout(self.hbox)

#-----------------------------------------------------------------------------
# Dockable Trace Visualization
#-----------------------------------------------------------------------------

# TODO: refactor out to trace controller / dock model

class TraceDock(QtWidgets.QToolBar):
    """
    A Qt 'Toolbar' to house the TraceBar visualizations.

    We use a Toolbar explicitly because they are given unique docking regions
    around the QMainWindow in Qt-based applications. This allows us to pin
    the visualizations to areas where they will not be dist
    """
    def __init__(self, core, parent=None):
        super(TraceDock, self).__init__(parent)
        self.core = core
        self.view = TraceView(core, self)
        self.setMovable(False)
        self.setContentsMargins(0, 0, 0, 0)
        self.addWidget(self.view)

    def attach_reader(self, reader):
        self.view.attach_reader(reader)
    
    def detach_reader(self):
        self.view.detach_reader()