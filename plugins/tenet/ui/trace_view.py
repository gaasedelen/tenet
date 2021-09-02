import logging
import traceback

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
from tenet.util.misc import assert_mainthread, register_callback, notify_callback
from tenet.integration.api import disassembler

logger = logging.getLogger("Tenet.UI.TraceView")

#------------------------------------------------------------------------------
# TraceView
#------------------------------------------------------------------------------

INVALID_IDX = -1

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
        self._image_base = None
        self._image_highlights = None
        self._image_selection = None
        self._image_border = None
        self._image_cursor = None
        self._image_final = None
        
        self._painter_base = None
        self._painter_highlights = None
        self._painter_selection = None
        self._painter_border = None
        self._painter_cursor = None
        self._painter_final = None

        self._dirty_base = True
        self._dirty_highlights = True

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

        # TODO
        self._trace_border = 1

        # zoom / region selection
        self._selection_border = 2
        self.color_selection = self.core.palette.trace_selection
        self.color_selection_border = self.core.palette.trace_selection_border
        self.pen_selection = QtGui.QPen(self.color_selection, self._selection_border, QtCore.Qt.SolidLine)
        self.brush_selection = QtGui.QBrush(QtCore.Qt.Dense6Pattern)
        self.brush_selection.setColor(self.color_selection_border)

        self._last_hovered = None

        self.start_idx = 0
        self.end_idx = 0

        self._selection_origin = INVALID_IDX
        self._idx_selection_start = INVALID_IDX
        self._idx_selection_end = INVALID_IDX

        self._executions = []
        self._reads = []
        self._writes = []

        # TODO: cell drawing
        self._cell_border = 0
        self._cell_min_border = 1
        self._cell_max_border = 1
        
        self._cell_height = 0
        self._cell_min_height = 2
        self._cell_max_height = 10
        
        self._cell_spacing = 0
        self._cell_min_spacing = self._cell_min_border

        #----------------------------------------------------------------------
        # Callbacks
        #----------------------------------------------------------------------

        self._selection_changed_callbacks = []

    #-------------------------------------------------------------------------
    # Properties
    #-------------------------------------------------------------------------

    @property
    def cells_visible(self):
        """
        Return True if the viz is drawing as cells.
        """
        return bool(self._cell_height)

    @property
    def density(self):
        """
        Return the 'density' of idx (instructions) per y-pixel of the viz.
        """
        density = (self.length / (self.height() - self._trace_border * 2))
        if density > 0:
            return density
        return -1

    @property
    def viz_rect(self):
        """
        Return the trace visualization rect.
        """
        x, y = self.viz_pos
        w, h = self.viz_size
        return QtCore.QRect(x, y, w, h)

    @property
    def viz_pos(self):
        """
        Return the (x, y) co-ordinates of the trace visualization.
        """
        return (self._trace_border, self._trace_border)

    @property
    def viz_size(self):
        """
        Return the (width, height) of the trace visualization.
        """
        w = max(0, int(self.width() - (self._trace_border * 2)))
        h = max(0, int(self.height() - (self._trace_border * 2)))
        return (w, h)

    #-------------------------------------------------------------------------
    # Public
    #-------------------------------------------------------------------------
    
    def attach_reader(self, reader):

        # clear out any existing state
        self.reset()

        # save the reader
        self.reader = reader

        # initialize state based on the reader
        self.set_zoom(0, reader.trace.length)

        # attach signals to the new reader
        reader.idx_changed(self.refresh)

    def set_zoom(self, start_idx, end_idx):
        """
        TODO
        """
        print("Setting Zoom!", start_idx, end_idx)
        assert start_idx < end_idx

        # save the first and last timestamps to be shown
        self.start_idx = start_idx
        self.end_idx = min(end_idx, self.reader.trace.length)

        # update drawing metrics 
        self._refresh_cell_metrics()

        # compute the number of instructions visible
        self.length = (self.end_idx - self.start_idx)

        # refresh/redraw relevant elements
        self._refresh_breakpoint_hits(self.core.breakpoints.model.focused_breakpoint)
        self.refresh()

    def set_selection(self, start_idx, end_idx):
        """
        TODO
        """
        self._idx_selection_end = end_idx
        self._idx_selection_start = start_idx
        self.refresh()

    def highlight_executions(self, idxs):
        self._executions = idxs
        self.refresh()

    def reset(self):
        """
        TODO
        """
        self.reader = None
        
        self.start_idx = 0
        self.end_idx = 0

        self._selection_origin = INVALID_IDX
        self._idx_selection_start = INVALID_IDX
        self._idx_selection_end = INVALID_IDX

        self._executions = []
        self._reads = []
        self._writes = []

        self.refresh()

    def refresh(self, *args):
        """
        TODO
        """
        #self._refresh_viz()
        self.update()
    
    #----------------------------------------------------------------------
    # Qt Overloads
    #----------------------------------------------------------------------

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
            #self._update_hover(event.y())
            self.update()

    def mousePressEvent(self, event):
        """
        Qt override to capture mouse button presses.
        """

        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            idx_origin = self._pos2idx(event.y())
            self._selection_origin = idx_origin
            self._idx_selection_start = idx_origin
            self._idx_selection_end = idx_origin
            
        return

    def mouseReleaseEvent(self, event):
        """
        Qt override to capture mouse button releases.
        """
        if not self.reader:
            return

        # if the left mouse button was released...
        if event.button() == QtCore.Qt.MouseButton.LeftButton:

            #
            # the initial 'click' origin is not set, so that means the 'click'
            # event did not start over this widget... or is something we
            # should just ignore.
            #

            if self._selection_origin == INVALID_IDX:
                return

            #
            # clear the selection origin as we will be consuming the
            # selection event in the followin codepath
            #

            self._selection_origin = INVALID_IDX

            #
            # if the user selection appears to be a 'click' vs a zoom / range
            # selection, then seek to the clicked address
            #

            if self._idx_selection_start == self._idx_selection_end:
                selected_idx = self._idx_selection_start

                #
                # if there is a visible event / highlight near the user's
                # click, we should lock onto that if it's close enough
                #

                closest_event_idx = self._get_closest_visible_idx(selected_idx)
                if closest_event_idx != INVALID_IDX:

                    # compute the distance between the click and the 'closest event'
                    current_y = self._idx2pos(self._idx_selection_start)
                    px_distance = self._compute_pixel_distance(current_y, closest_event_idx)

                    if px_distance < LOCKON_DISTANCE:
                        selected_idx = closest_event_idx

                #
                # jump to the selected area
                #

                #print(f"Jumping to {selected_idx:,}")
                self.reader.seek(selected_idx)
                
                self._notify_selection_changed(selected_idx, selected_idx)
                self.refresh()
                return

            #
            # TODO
            #

            if self._is_zoom:
                new_start = self._idx_selection_start
                new_end = self._idx_selection_end
                self._idx_selection_start = self._idx_selection_end = -1
                self.set_zoom(new_start, new_end)
                self._notify_selection_changed(new_start, new_end)
            else:
                self._notify_selection_changed(self._idx_selection_start, self._idx_selection_end)

    def leaveEvent(self, event):
        #self.refresh()
        pass

    #def keyPressEvent(self, e):
    #    #print("PRESSING", e.key(), e.modifiers())
    #    pass

    #def keyReleaseEvent(self, e):
    #    #print("RELEASING", e.key(), e.modifiers())
    #    pass

    #def resizeEvent(self, event):
    #    size = event.size()

    #    # compute the 'drawable' tracebar dimensions
    #    self._width = max(0, self.width() - BORDER_SIZE * 2)
    #    self._height = max(0, self.height() - BORDER_SIZE * 2)

    #    #self._refresh_breakpoint_hits(breakpoint)
    #    self.refresh()

    #-------------------------------------------------------------------------
    # Helpers (Internal)
    #-------------------------------------------------------------------------
    #
    #    NOTE: this stuff should probably only be called by the 'mainthread'
    #    to ensure density / viz dimensions and stuff don't change.
    #

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

        print(f" HOVERED IDX {hovered_idx:,}, CLOSEST IDX {closest_idx:,}, DIST {px_distance}")

        painter = self._painter_base
        LINE_WIDTH = self.width() - (BORDER_SIZE * 2)

        # unpaint the last hovered line with the position/color we stored for it
        if self._last_hovered:
            old_data, prev_y = self._last_hovered
            length = min(len(old_data), self._image_base.width() * 4)
            current_data = self._image_base.scanLine(prev_y).asarray(length)
            for i in range(length):
                current_data[i] = old_data[i]

        # nothing close, so don't bother painting a highlight
        if px_distance >= LOCKON_DISTANCE:
            self._last_hovered = None
            #print("NOTHING CLOSE!")
            # TODO: I JUST COMMENTED THIS OUT
            #self._draw_cursor(painter)
            return

        locked_y = self._idx2pos(closest_idx)

        # overwrite last_hovered with the latest hover position / color we will stomp
        current_line_data = self._image_base.scanLine(locked_y)
        old_data = [x for x in current_line_data.asarray(4 * self._image_base.width())]
        self._last_hovered = (old_data, locked_y)
        #self._last_hovered = (self._image.pixelColor(LINE_WIDTH//2, locked_y), locked_y)
        
        # paint the currently hovered line
        painter.setPen(self.cursor_pen)
        painter.drawLine(BORDER_SIZE, locked_y, LINE_WIDTH, locked_y)
        print("PAINTED NEW!")

        # TODO: I JUST COMMENTED THIS OUT
        #self._draw_cursor(painter) 

    def _refresh_cell_metrics(self):

        # reset cell metrics
        self._cell_height = 0
        self._cell_border = 0
        self._cell_spacing = 0
        
        # how many 'instruction' cells *must* be shown based on current selection
        num_cell = self.end_idx - self.start_idx
        if not num_cell:
            return

        # how many 'y' pixels are available, per cell (including spacing, between cells)
        _, viz_h = self.viz_size
        given_space_per_cell = viz_h / num_cell
        
        # compute the smallest possible cell height, with overlapping cell borders
        min_full_cell_height = self._cell_min_height + self._cell_min_border

        # don't draw trace as cells if the density is too high
        if given_space_per_cell < min_full_cell_height:
            #print(f"Not gonna use cell metrics! Given pixels per cell {given_space_per_cell}, min req {min_full_cell_height}")
            return
        
        # compute the pixel height of a cell at maximum height (including borders)
        max_cell_height_with_borders = self._cell_max_height + self._cell_max_border * 2

        # compute how much leftover space there is between cells
        spacing_between_max_cells = given_space_per_cell - max_cell_height_with_borders

        # maximum sized instruction cells, with 'infinite' possible spacing between cells
        if spacing_between_max_cells > max_cell_height_with_borders:
            #print("Infinite spacing with max cells!")
            self._cell_border = self._cell_max_border
            self._cell_height = self._cell_max_height
            self._cell_spacing = spacing_between_max_cells
            return
            
        self._cell_height  = max(self._cell_min_height, min(int(given_space_per_cell * 0.95), self._cell_max_height))
        self._cell_border  = max(self._cell_min_border, min(int(given_space_per_cell * 0.05), self._cell_max_border))
        self._cell_spacing = int(given_space_per_cell - (self._cell_height + self._cell_border * 2))
        
        #print(f"Given: {given_space_per_cell}, Height {self._cell_height}, Border: {self._cell_border}, Spacing: {self._cell_spacing}")

        # if there's not enough to justify having spacing, use shared borders
        if self._cell_spacing < self._cell_min_spacing:
            self._cell_spacing = self._cell_min_border * -2
            #print("Tweaked to use overlapping borders")

        # compute the final number of y pixels used by each 'cell' (an executed instruction)
        used_space_per_cell = self._cell_height + self._cell_border * 2 + self._cell_spacing

        # compute how many cells we can *actually* show in the space available
        num_cell_allowed = int(viz_h / used_space_per_cell) + 1
        #print(f"Num Cells {num_cell} vs Available Space {num_cell_allowed}")

        # TODO: test edge case if called towards very end of trace?
        self.end_idx = min(self.start_idx + num_cell_allowed, self.reader.trace.length)

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

        # TODO cleanup all these if / conditionals
        if not self.isVisible():
            return

        if not (self.core.reader and breakpoint):
            return

        density = self.density
        if density == -1:
            return

        if breakpoint.type == BreakpointType.EXEC:
            
            self._executions = self.core.reader.get_executions_between(breakpoint.address, self.start_idx, self.end_idx, density)

        elif breakpoint.type == BreakpointType.ACCESS:

            if breakpoint.length == 1:
                self._reads, self._writes = self.core.reader.get_memory_accesses_between(breakpoint.address, self.start_idx, self.end_idx, density)
            else:
                self._reads, self._writes = self.core.reader.get_memory_region_accesses_between(breakpoint.address, breakpoint.length, self.start_idx, self.end_idx, density)

        else:
            raise NotImplementedError

    @assert_mainthread
    def _idx2pos(self, idx):
        """
        Translate a given idx to its first y coordinate.
        """
        if idx < self.start_idx or idx >= self.end_idx:
            logger.warn(f"idx2pos failed (start: {self.start_idx:,} idx: {idx:,} end: {self.end_idx:,}")
            return -1

        density = self.density
        if density == -1:
            logger.warn(f"idx2pos failed (density == -1)")
            return -1

        # convert the absolute idx to one that is 'relative' to the viz 
        relative_idx = idx - self.start_idx

        # re-base y to the start of the viz region
        _, y = self.viz_pos

        # 
        # compute and return an 'approximate' y position of the given idx
        # when the visualization is not using cell metrics (too dense)
        #
        
        if not self.cells_visible:
            y += int(relative_idx / density)

            # sanity check
            _, viz_y = self.viz_pos
            _, viz_h = self.viz_size
            assert y >= viz_y
            assert y < (viz_y + viz_h)

            # return the approximate y position of the given timestamp
            return y

        #assert self._cell_spacing % 2 == 0

        # compute the y position of the 'first' cell
        y += self._cell_spacing / 2   # pad out from top
        y += self._cell_border        # top border of cell

        # compute the y position of any given cell after the first
        y += self._cell_height * relative_idx  # cell body
        y += self._cell_border * relative_idx  # cell bottom border
        y += self._cell_spacing * relative_idx # full space between cells
        y += self._cell_border * relative_idx  # cell top border

        # return the y position of the cell corresponding to the given timestamp
        return y

    def _pos2idx(self, y):
        """
        Translate a given Y coordinate to an approximate idx.
        """
        _, viz_y = self.viz_pos
        _, viz_h = self.viz_size

        if y < viz_y or y >= viz_y + viz_h:
            logger.warn(f"pos2idx failed (viz_y: {viz_y} y: {y} viz_y+viz_h: {viz_y+viz_h}")
            return -1
        
        density = self.density
        if density == -1:
            logger.warn(f"pos2idx failed (density == -1)")
            return -1

        # translate/rebase global y to viz relative y
        y -= self._trace_border

        # compute the approximate relative idx using the instruction density metric
        relative_idx = round(y * density)

        # convert the viz-relative idx, to its global trace idx timestamp
        idx = self.start_idx + relative_idx

        # clamp idx to the start / end of visible tracebar range
        if idx < self.start_idx:
            idx = self.start_idx
        elif idx >= self.end_idx:
            idx = self.end_idx - 1

        return idx

    def _compute_pixel_distance(self, y, idx):
        """
        Compute the pixel distance from a given Y to an idx.
        """

        # get the y position of the given idx
        y_idx = self._idx2pos(idx)
        if y_idx == -1:
            return -1

        # return the on-screen pixel distance between the two y's 
        return abs(y - y_idx)

    def _update_selection(self, y):
        """
        TODO
        """
        idx_event = self._pos2idx(y)

        if idx_event > self._selection_origin:
            self._idx_selection_start = self._selection_origin
            self._idx_selection_end = idx_event
        else:
            self._idx_selection_end = self._selection_origin
            self._idx_selection_start = idx_event

    def _get_closest_visible_idx(self, idx):
        """
        Return the closest idx (timestamp) to the given idx.
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

    #-------------------------------------------------------------------------
    # Drawing
    #-------------------------------------------------------------------------

    def paintEvent(self, event):

        # TODO: remove??
        if self.height() == 0 or self.width() == 0:
            return
        
        # TODO 
        self._last_hovered = None

        viz_x, viz_y = self.viz_pos 

        painter = QtGui.QPainter(self)

        #
        # draw instructions / trace landscape
        #

        self._draw_base()
        painter.drawImage(0, 0, self._image_base)

        #
        # draw accesses along the trace timeline
        #

        self._draw_highlights()
        painter.drawImage(0, 0, self._image_highlights)
                
        #
        # draw user region selection over trace timeline
        #
        
        self._draw_selection()
        painter.drawImage(0, 0, self._image_selection)
        
        #
        # draw border around trace timeline
        #

        self._draw_border()
        painter.drawImage(0, 0, self._image_border)

        # 
        # draw current trace position cursor
        #

        self._draw_cursor()
        painter.drawImage(0, 0, self._image_cursor)

        #painter.drawImage(0, 0, self._image_final)

    def _draw_base(self):
        """
        TODO
        """
        if not self._dirty_base:
            return
            
        # 
        # NOTE: DO NOT REMOVE !!! Qt will CRASH if we do not explicitly delete
        # these here (dangling internal pointer to device/image otherwise?!?)
        #

        del self._painter_base

        #
        # the base image will contain a raw drawing of the trace or cells
        # depending on the level of granularity the viz is configured for.
        #

        self._image_base = QtGui.QImage(self.width(), self.height(), QtGui.QImage.Format_ARGB32)
        self._image_base.fill(self.core.palette.trace_bedrock)
        #self._image_base.fill(QtGui.QColor("red")) # NOTE/debug
        self._painter_base = QtGui.QPainter(self._image_base)

        # redraw instructions
        if self.cells_visible:
            self._draw_trace_cells(self._painter_base)
        else:
            self._draw_trace_landscape(self._painter_base)

    def _draw_trace_landscape(self, painter):
        """
        Draw a 'zoomed out' trace visualization.
        """
        dctx = disassembler[self.core]
        viz_w, viz_h = self.viz_size
        viz_x, viz_y = self.viz_pos
        
        for i in range(viz_h):

            # convert a y pixel in the viz region to an executed address
            wid_y = viz_y + i
            idx = self._pos2idx(wid_y)
            address = self.reader.get_ip(idx)

            # select the color for instructions that can be viewed with Tenet
            if dctx.is_mapped(address):
                painter.setPen(self.core.palette.trace_instruction)

            # unexplorable parts of the trace are 'greyed' out (eg, not in IDB)
            else:
                painter.setPen(self.core.palette.trace_unmapped)

            # paint the current line
            painter.drawLine(viz_x, wid_y, viz_w, wid_y)

    def _draw_trace_cells(self, painter):
        """
        Draw a 'zoomed in', cell-based, trace visualization.
        """

        # configure how the border between cells will be drawn
        color = self.core.palette.trace_border
        if self._cell_spacing < 0:
            color = self.core.palette.hex_separator # TODO

        border_pen = QtGui.QPen(color, self._cell_border, QtCore.Qt.SolidLine)
        painter.setPen(border_pen)

        #
        # compute the default color to use for each cell
        #
        # if there is no spacing between cells, that means they are going to
        # be relatively small and have shared 'cell walls' (borders)
        # 
        # we attempt to maximize contrast between border and cell color, while
        # attempting to keep the tracebar color visually consistent
        #

        if self._cell_spacing < 0:
            ratio = (self._cell_border / (self._cell_height - 1)) * 0.5
            lighten = 100 + int(ratio * 100)
            cell_color = self.core.palette.trace_instruction.lighter(lighten)
            #print(f"Lightened by {lighten}% (Border: {self._cell_border}, Body: {self._cell_height}")
        else:
            cell_color = self.core.palette.trace_instruction

        painter.setBrush(cell_color)

        #
        # draw the cells
        #

        viz_x, viz_y = self.viz_pos
        viz_w, viz_h = self.viz_size

        x = viz_x + self._cell_border * -1
        w = viz_w + self._cell_border
        h = self._cell_height
        
        # draw each cell + border 
        for idx in range(self.start_idx, self.end_idx):
            y = self._idx2pos(idx)
            painter.drawRect(x, y, w, h)

    def _draw_highlights(self):
        """
        Draw trace event highlights.
        """
        if not self._dirty_highlights:
            return

        # 
        # NOTE: DO NOT REMOVE !!! Qt will CRASH if we do not explicitly delete
        # these here (dangling internal pointer to device/image otherwise?!?)
        #

        del self._painter_highlights

        #
        # interactive highlights such as the user cursor, selection, memory,
        # or breakpoints are drawn to a different layer which will overlay
        # the base image
        #

        self._image_highlights = QtGui.QImage(self.width(), self.height(), QtGui.QImage.Format_ARGB32)
        self._image_highlights.fill(QtCore.Qt.transparent)
        self._painter_highlights = QtGui.QPainter(self._image_highlights)

        if self.cells_visible:
            self._draw_highlights_cells(self._painter_highlights)
        else:
            self._draw_highlights_landscape(self._painter_highlights)

    def _draw_highlights_cells(self, painter):
        """
        TODO
        """
        viz_w, _ = self.viz_size
        viz_x, _ = self.viz_pos
        
        access_sets = \
        [
            (self._reads, self.color_read),
            (self._writes, self.color_write),
            (self._executions, self.color_exec),
        ]

        painter.setPen(QtCore.Qt.NoPen)
                
        h = self._cell_height - self._cell_border
        
        for entries, cell_color in access_sets:
            painter.setBrush(cell_color)

            for idx in entries:

                # TODO: is this even a concern anymore? 
                # skip entries that fall outside the visible zoom
                if not(self.start_idx <= idx < self.end_idx):
                    continue
                
                # slight tweaks, we are only drawing cell body, no borders
                y = self._idx2pos(idx) + self._cell_border

                # draw cell body
                painter.drawRect(viz_x, y, viz_w, h)

    def _draw_highlights_landscape(self, painter):
        """
        Draw read / write / execs accesses on the trace timeline.
        """
        viz_w, _ = self.viz_size
        viz_x, _ = self.viz_pos

        access_sets = \
        [
            (self._reads, self.color_read),
            (self._writes, self.color_write),
            (self._executions, self.color_exec),
        ]

        for entries, color in access_sets:
            painter.setPen(color)

            for idx in entries:
                
                # TODO: is this even a concern anymore? 
                # skip entries that fall outside the visible zoom
                if not(self.start_idx <= idx < self.end_idx):
                    continue
                
                y = self._idx2pos(idx)
                painter.drawLine(viz_x, y, viz_w, y)

    def _draw_cursor(self):
        """
        Draw the user cursor / current position in the trace.
        """

        # TODO: remove?
        if not self.reader:
            return

        path = QtGui.QPainterPath()
        
        size = 13
        assert size % 2, "Cursor triangle size must be odd"

        # TODO        
        del self._painter_cursor
        self._image_cursor = QtGui.QImage(self.width(), self.height(), QtGui.QImage.Format_ARGB32)
        self._image_cursor.fill(QtCore.Qt.transparent)
        self._painter_cursor = QtGui.QPainter(self._image_cursor)

        # rebase the absolute trace cursor idx to the current 'zoomed' view
        #relative_idx = self.reader.idx - self.start_idx
        #if relative_idx < 0:
        #    return False

        # compute the y coordinate / line to center the user cursor around
        cursor_y = self._idx2pos(self.reader.idx)
        if cursor_y == -1:
            return
            
        if self.cells_visible:
            cell_y = cursor_y + self._cell_border
            cell_body_height = self._cell_height - self._cell_border
            cursor_y += self._cell_height/2

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

        viz_x, _ = self.viz_pos
        viz_w, _ = self.viz_size

        if self.cells_visible:
            self._painter_cursor.setPen(QtCore.Qt.NoPen)
            self._painter_cursor.setBrush(self.color_cursor)
            self._painter_cursor.drawRect(viz_x, cell_y, viz_w, cell_body_height)
        else:
            self._painter_cursor.setPen(self.cursor_pen)
            self._painter_cursor.drawLine(0, cursor_y, self.width(), cursor_y)
        
        # paint the defined triangle
        # TODO: don't hardcode colors
        self._painter_cursor.setPen(QtCore.Qt.black)
        self._painter_cursor.setBrush(QtGui.QBrush(QtGui.QColor("red")))
        self._painter_cursor.drawPath(path)

    def _draw_selection(self):
        """
        Draw a region selection rect.
        """

        # 
        # NOTE: DO NOT REMOVE !!! Qt will CRASH if we do not explicitly delete
        # these here (dangling internal pointer to device/image otherwise?!?)
        #

        del self._painter_selection

        #
        # TODO
        #

        viz_w, viz_h = self.viz_size
        self._image_selection = QtGui.QImage(self.width(), self.height(), QtGui.QImage.Format_ARGB32)
        self._image_selection.fill(QtCore.Qt.transparent)
        self._painter_selection = QtGui.QPainter(self._image_selection)

        #print("DRAWING SELECTION?", self._selection_start, self._selection_end)
        if self._idx_selection_start == self._idx_selection_end:
            return

        start_y = self._idx2pos(self._idx_selection_start)
        end_y = self._idx2pos(self._idx_selection_end)

        self._painter_selection.setBrush(self.brush_selection)
        self._painter_selection.setPen(self.pen_selection)

        # TODO/FUTURE: real border math
        viz_x, viz_y = self.viz_pos
        
        x = viz_x
        y = start_y
        w = viz_w
        h = end_y - start_y

        # draw the screen door / selection rect
        self._painter_selection.drawRect(x, y, w, h)

    def _draw_border(self):
        """
        Draw the border around the trace timeline.
        """

        # 
        # NOTE: DO NOT REMOVE !!! Qt will CRASH if we do not explicitly delete
        # these here (dangling internal pointer to device/image otherwise?!?)
        #

        del self._painter_border

        #
        # TODO
        #

        wid_w = self.width()
        wid_h = self.height()
        
        self._image_border = QtGui.QImage(wid_w, wid_h, QtGui.QImage.Format_ARGB32)
        self._image_border.fill(QtCore.Qt.transparent)
        self._painter_border = QtGui.QPainter(self._image_border)

        color = self.core.palette.trace_border
        #color = QtGui.QColor("red") # NOTE: for dev/debug testing
        border_pen = QtGui.QPen(color, self._trace_border, QtCore.Qt.SolidLine)
        self._painter_border.setPen(border_pen)

        w = wid_w - self._trace_border
        h = wid_h - self._trace_border

        # draw the border around the tracebar using a blank rect + stroke (border)
        self._painter_border.drawRect(0, 0, w, h)

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
        
#-----------------------------------------------------------------------------
# TODO
#-----------------------------------------------------------------------------

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