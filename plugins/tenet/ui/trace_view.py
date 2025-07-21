import logging

from tenet.util.qt import *
from tenet.util.misc import register_callback, notify_callback
from tenet.integration.api import disassembler

logger = logging.getLogger("Tenet.UI.TraceView")

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

#------------------------------------------------------------------------------
# TraceView
#------------------------------------------------------------------------------

INVALID_POS = -1
INVALID_IDX = -1
INVALID_DENSITY = -1

class TraceBar(QtWidgets.QWidget):
    """
    A trace visualization.
    """

    def __init__(self, pctx, zoom=False, parent=None):
        super(TraceBar, self).__init__(parent)
        self.pctx = pctx
        self.reader = None
        self._is_zoom = zoom

        # misc qt/widget settings
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        self.setMouseTracking(True)
        self.setMinimumSize(32, 32)
        self._resize_timer = QtCore.QTimer(self)
        self._resize_timer.setSingleShot(True)
        self._resize_timer.timeout.connect(self._resize_stopped)

        # the first and last visible idx in this visualization
        self.start_idx = 0
        self.end_idx = 0
        self._end_idx_internal = 0
        self._last_trace_idx = 0

        # the 'uncommitted' / in-progress user selection of a trace region
        self._idx_pending_selection_origin = INVALID_IDX
        self._idx_pending_selection_start = INVALID_IDX
        self._idx_pending_selection_end = INVALID_IDX

        # the committed user selection of a trace region
        self._idx_selection_start = INVALID_IDX
        self._idx_selection_end = INVALID_IDX

        # the idxs that should be highlighted based on user queries
        self._idx_reads = []
        self._idx_writes = []
        self._idx_executions = []

        # the magnetism distance (in pixels) for cursor clicks on viz events
        self._magnetism_distance = 4
        self._hovered_idx = INVALID_IDX

        # listen for breakpoint changed events
        pctx.breakpoints.model.breakpoints_changed(self._breakpoints_changed)

        #----------------------------------------------------------------------
        # Styling
        #----------------------------------------------------------------------

        # the width (in pixels) of the border around the trace bar
        self._trace_border = 1

        # the width (in pixels) of the border around trace cells
        self._cell_border = 0 # computed dynamically
        self._cell_min_border = 1
        self._cell_max_border = 1

        # the height (in pixels) of the trace cells
        self._cell_height = 0 # computed dynamically
        self._cell_min_height = 2
        self._cell_max_height = 10

        # the amount of space between cells (in pixels)
        # - NOTE: no limit to cell spacing at max magnification!
        self._cell_spacing = 0 # computed dynamically
        self._cell_min_spacing = self._cell_min_border

        # the width (in pixels) of the border around user region selection
        self._selection_border = 2

        # create the rest of the painting vars
        self._init_painting()

        #----------------------------------------------------------------------
        # Callbacks
        #----------------------------------------------------------------------

        self._selection_changed_callbacks = []

    def _init_painting(self):
        """
        Initialize widget/trace painting elements.
        """
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

        self._pen_cursor = QtGui.QPen(self.pctx.palette.trace_cursor_highlight, 1, QtCore.Qt.SolidLine)

        self._pen_selection = QtGui.QPen(self.pctx.palette.trace_selection, self._selection_border, QtCore.Qt.SolidLine)
        self._brush_selection = QtGui.QBrush(QtCore.Qt.Dense6Pattern)
        self._brush_selection.setColor(self.pctx.palette.trace_selection_border)

        self._last_hovered = INVALID_IDX

    #-------------------------------------------------------------------------
    # Properties
    #-------------------------------------------------------------------------

    @property
    def length(self):
        """
        Return the number of idx visible in the trace visualization.
        """
        return (self.end_idx - self.start_idx)

    @property
    def cells_visible(self):
        """
        Return True if the trace visualization is drawing as cells.
        """
        return bool(self._cell_height)

    @property
    def density(self):
        """
        Return the density of idx (instructions) per y-pixel of the trace visualization.
        """
        density = (self.length / (self.height() - self._trace_border * 2))
        if density > 0:
            return density
        return INVALID_DENSITY

    @property
    def viz_rect(self):
        """
        Return a QRect defining the drawable trace visualization.
        """
        x, y = self.viz_pos
        w, h = self.viz_size
        return QtCore.QRect(x, y, w, h)

    @property
    def viz_pos(self):
        """
        Return (x, y) coordinates of the drawable trace visualization.
        """
        return (self._trace_border, self._trace_border)

    @property
    def viz_size(self):
        """
        Return (width, height) of the drawable trace visualization.
        """
        w = max(0, int(self.width() - (self._trace_border * 2)))
        h = max(0, int(self.height() - (self._trace_border * 2)))
        return (w, h)

    #-------------------------------------------------------------------------
    # Public
    #-------------------------------------------------------------------------

    def attach_reader(self, reader):
        """
        Attach a trace reader to this controller.
        """
        self.reset()

        # attach the new reader
        self.reader = reader

        # initialize state based on the reader
        self.set_bounds(0, reader.trace.length)

        # attach signals to the new reader
        reader.idx_changed(self.refresh)

    def set_bounds(self, start_idx, end_idx):
        """
        Set the idx bounds of the trace visualization.
        """
        assert end_idx > start_idx, f"Invalid Bounds ({start_idx}, {end_idx})"

        # set the bounds of the trace
        self.start_idx = max(0, start_idx)
        self.end_idx = end_idx
        self._end_idx_internal = end_idx

        # update drawing metrics, note that this can 'tweak' end_idx to improve cell rendering
        self._refresh_painting_metrics()

        # compute the number of instructions visible
        self._last_trace_idx = min(self.reader.trace.length, self.end_idx)

        # refresh/redraw relevant elements
        self._refresh_trace_highlights()
        self.refresh()

        # return the final / selected bounds
        return (self.start_idx, self.end_idx)

    def set_selection(self, start_idx, end_idx):
        """
        Set the selection region bounds.
        """
        assert end_idx >= start_idx
        self._idx_selection_start = start_idx
        self._idx_selection_end = end_idx
        self.refresh()

    def reset(self):
        """
        Reset the trace visualization.
        """
        self.reader = None

        self.start_idx = 0
        self.end_idx = 0
        self._last_trace_idx = 0

        self._idx_pending_selection_origin = INVALID_IDX
        self._idx_pending_selection_start = INVALID_IDX
        self._idx_pending_selection_end = INVALID_IDX

        self._idx_selection_start = INVALID_IDX
        self._idx_selection_end = INVALID_IDX

        self._idx_reads = []
        self._idx_writes = []
        self._idx_executions = []

        self._refresh_painting_metrics()
        self.refresh()

    def refresh(self, *args):
        """
        Refresh the trace visualization.
        """
        self.update()

    #----------------------------------------------------------------------
    # Qt Overloads
    #----------------------------------------------------------------------

    def mouseMoveEvent(self, event):
        """
        Qt overload to capture mouse movement events.
        """
        if not self.reader:
            return

        # mouse moving while holding left button
        if event.buttons() == QtCore.Qt.MouseButton.LeftButton:
            self._update_selection(event.y())
            self.refresh()
            return

        # simple mouse hover over viz
        self._update_hover(event.y())
        self.refresh()

    def mousePressEvent(self, event):
        """
        Qt overload to capture mouse button presses.
        """
        if not self.reader:
            return

        # left mouse button was pressed (but not yet released!)
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            idx_origin = self._pos2idx(event.y())
            self._idx_pending_selection_origin = idx_origin
            self._idx_pending_selection_start = idx_origin
            self._idx_pending_selection_end = idx_origin

        return

    def mouseReleaseEvent(self, event):
        """
        Qt overload to capture mouse button releases.
        """
        if not self.reader:
            return

        # if the left mouse button was released...
        if event.button() == QtCore.Qt.MouseButton.LeftButton:

            #
            # no selection origin? this means the click probably started
            # off this widget, and the user moved their mouse over viz
            # ... before releasing... which is not something we care about
            #

            if self._idx_pending_selection_origin == INVALID_IDX:
                return

            # if the mouse press & release was on the same idx, probably a click
            if self._idx_pending_selection_start == self._idx_pending_selection_end:
                self._commit_click()

            # a range was selected, so accept/commit it
            else:
                self._commit_selection()

    def leaveEvent(self, _):
        """
        Qt overload to capture the mouse hover leaving the widget.
        """
        self._hovered_idx = INVALID_IDX
        self.refresh()

    def wheelEvent(self, event):
        """
        Qt overload to capture wheel events.
        """
        if not self.reader:
            return

        # holding the shift key while scrolling is used to 'step over'
        mod_keys = QtGui.QGuiApplication.keyboardModifiers()
        step_over = bool(mod_keys & QtCore.Qt.ShiftModifier)

        # scrolling up, so step 'backwards' through the trace
        if event.angleDelta().y() > 0:
            self.reader.step_backward(1, step_over)

        # scrolling down, so step 'forwards' through the trace
        elif event.angleDelta().y() < 0:
            self.reader.step_forward(1, step_over)

        self.refresh()
        event.accept()

    def resizeEvent(self, _):
        """
        Qt overload to capture resize events for the widget.
        """
        self._resize_timer.start(500)

    #-------------------------------------------------------------------------
    # Helpers (Internal)
    #-------------------------------------------------------------------------
    #
    #    NOTE: this stuff should probably only be called by the 'mainthread'
    #    to ensure density / viz dimensions and stuff don't change.
    #

    def _resize_stopped(self):
        """
        Delayed handler of resize events.

        We delay handling resize events because several resize events can
        trigger when a user is dragging to resize a window. we only really
        care to recompute the visualization when they stop 'resizing' it.
        """
        self.set_bounds(self.start_idx, self._end_idx_internal)

    def _refresh_painting_metrics(self):
        """
        Refresh any metrics and calculations required to paint the widget.
        """
        self._cell_height = 0
        self._cell_border = 0
        self._cell_spacing = 0

        # how many 'instruction' cells *must* be shown based on current selection?
        num_cell = self._end_idx_internal - self.start_idx
        if not num_cell:
            return

        # how many 'y' pixels are available, per cell (including spacing, between cells)
        _, viz_h = self.viz_size
        given_space_per_cell = viz_h / num_cell

        # compute the smallest possible cell height, with overlapping cell borders
        min_full_cell_height = self._cell_min_height + self._cell_min_border

        # don't draw the trace vizualization as cells if the density is too high
        if given_space_per_cell < min_full_cell_height:
            #logger.debug(f"No need for cells -- {given_space_per_cell}, min req {min_full_cell_height}")
            return

        # compute the pixel height of a cell at maximum height (including borders)
        max_cell_height_with_borders = self._cell_max_height + self._cell_max_border * 2

        # compute how much leftover space there is to use between cells
        spacing_between_max_cells = given_space_per_cell - max_cell_height_with_borders

        # maximum sized instruction cells, with 'infinite' possible spacing between cells
        if spacing_between_max_cells > max_cell_height_with_borders:
            self._cell_border = self._cell_max_border
            self._cell_height = self._cell_max_height
            self._cell_spacing = spacing_between_max_cells
            return

        # dynamically compute cell dimensions for drawing
        self._cell_height  = max(self._cell_min_height, min(int(given_space_per_cell * 0.95), self._cell_max_height))
        self._cell_border  = max(self._cell_min_border, min(int(given_space_per_cell * 0.05), self._cell_max_border))
        self._cell_spacing = int(given_space_per_cell - (self._cell_height + self._cell_border * 2))
        #logger.debug(f"Dynamic cells -- Given: {given_space_per_cell}, Height {self._cell_height}, Border: {self._cell_border}, Spacing: {self._cell_spacing}")

        # if there's not enough to justify having spacing, use shared borders between cells (usually very small cells)
        if self._cell_spacing < self._cell_min_spacing:
            self._cell_spacing = self._cell_min_border * -2

        # compute the final number of y pixels used by each 'cell' (an executed instruction)
        used_space_per_cell = self._cell_height + self._cell_border * 2 + self._cell_spacing

        # compute how many cells we can *actually* show in the space available
        num_cell_allowed = int(viz_h / used_space_per_cell) + 1
        #logger.debug(f"Num Cells {num_cell} vs Available Space {num_cell_allowed}")

        self.end_idx = self.start_idx + num_cell_allowed

    def _idx2pos(self, idx):
        """
        Translate a given idx to its first Y coordinate.
        """
        if idx < self.start_idx or idx >= self.end_idx:
            #logger.warn(f"idx2pos failed (start: {self.start_idx:,} idx: {idx:,} end: {self.end_idx:,}")
            return INVALID_POS

        density = self.density
        if density == INVALID_DENSITY:
            #logger.warn(f"idx2pos failed (INVALID_DENSITY)")
            return INVALID_POS

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
        y += self._cell_spacing // 2   # pad out from top
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

        # clamp clearly out-of-bounds requests to the start/end idx values
        if y < viz_y:
            return self.start_idx
        elif y >= viz_y + viz_h:
            return self.end_idx - 1

        density = self.density
        if density == INVALID_DENSITY:
            #logger.warn(f"pos2idx failed (INVALID_DENSITY)")
            return INVALID_IDX

        # translate/rebase global y to viz relative y
        y -= self._trace_border

        # compute the relative idx based on how much space is used per cell
        if self.cells_visible:

            # this is how many vertical pixel each cell uses, including spacing to the next cell
            used_space_per_cell = self._cell_height + self._cell_border * 2 + self._cell_spacing

            # compute relative idx for cell-based views
            y -= self._cell_border
            relative_idx = int(y / used_space_per_cell)

        # compute the approximate relative idx using the instruction density metric
        else:
            relative_idx = round(y * density)

        # convert the viz-relative idx, to its global trace idx timestamp
        idx = self.start_idx + relative_idx

        # clamp idx to the start / end of visible tracebar range
        return self._clamp_idx(idx)

    def _compute_pixel_distance(self, y, idx):
        """
        Compute the pixel distance from a given Y to an idx.
        """

        # get the y pixel position of the given idx
        y_idx = self._idx2pos(idx)
        if y_idx == INVALID_POS:
            return -1

        #
        # if the visualization drawing cells, adjust the reported y coordinate
        # of the given idx to the center of the cell. this makes distance
        # calculations more correct
        #

        if self.cells_visible:
            y_idx += int(self._cell_height/2)

        # return the on-screen pixel distance between the two y coords
        return abs(y - y_idx)

    def _update_hover(self, current_y):
        """
        Update the trace visualization based on the mouse hover.
        """
        self._hovered_idx = INVALID_IDX

        # see if there's an interesting trace event close to the hover
        hovered_idx = self._pos2idx(current_y)
        closest_idx = self._get_closest_highlighted_idx(hovered_idx)

        #
        # if the closest highlighted event (mem access, breakpoint)
        # is outside the trace view bounds, then we don't need to
        # do any special hover highlighting...
        #

        if not(self.start_idx <= closest_idx < self.end_idx):
            return

        #
        # compute the on-screen pixel distance between the hover and the
        # closest highlighted event
        #

        px_distance = self._compute_pixel_distance(current_y, closest_idx)
        #logger.debug(f"hovered idx {hovered_idx:,}, closest idx {closest_idx:,}, dist {px_distance} (start: {self.start_idx:,} end: {self.end_idx:,}")
        if px_distance == -1:
            return

        # clamp the lock-on distance depending on the scale of zoom / cell size
        lockon_distance = max(self._magnetism_distance, self._cell_height)

        #
        # if the trace event is within the magnetized distance of the user
        # cursor, lock on to it. this makes 'small' things easier to click
        #

        if px_distance < lockon_distance:
            self._hovered_idx = closest_idx

    def _update_selection(self, y):
        """
        Update the user region selection of the trace visualization based on the current y.
        """
        idx_event = self._pos2idx(y)

        if idx_event > self._idx_pending_selection_origin:
            self._idx_pending_selection_start = self._idx_pending_selection_origin
            self._idx_pending_selection_end = idx_event
        else:
            self._idx_pending_selection_end = self._idx_pending_selection_origin
            self._idx_pending_selection_start = idx_event

        self._idx_selection_start = INVALID_IDX
        self._idx_selection_end = INVALID_IDX

    def _global_selection_changed(self, start_idx, end_idx):
        """
        Handle selection behavior specific to a 'global' trace visualizations.
        """
        if start_idx == end_idx:
            return
        self.set_selection(start_idx, end_idx)

    def _zoom_selection_changed(self, start_idx, end_idx):
        """
        Handle selection behavior specific to a 'zoomer' trace visualizations.
        """
        if start_idx == end_idx:
            self.hide()
        else:
            self.show()
            self.set_bounds(start_idx, end_idx)

    def _commit_click(self):
        """
        Accept a click event.
        """
        selected_idx = self._idx_pending_selection_start

        # use a 'magnetized' selection, if available
        if self._hovered_idx != INVALID_IDX:
            selected_idx = self._hovered_idx
            self._hovered_idx = INVALID_IDX

        # reset pending selection
        self._idx_pending_selection_origin = INVALID_IDX
        self._idx_pending_selection_start = INVALID_IDX
        self._idx_pending_selection_end = INVALID_IDX

        # does the click fall within the existing selected region?
        within_region = (self._idx_selection_start <= selected_idx <= self._idx_selection_end)

        # nope click is outside the region, so clear the region selection
        if not within_region:
            self._idx_selection_start = INVALID_IDX
            self._idx_selection_end = INVALID_IDX
            self._notify_selection_changed(INVALID_IDX, INVALID_IDX)

        #print(f"Jumping to {selected_idx:,}")
        self.reader.seek(selected_idx)
        self.refresh()

    def _commit_selection(self):
        """
        Accept a selection event.
        """
        new_start = self._idx_pending_selection_start
        new_end = self._idx_pending_selection_end

        # reset pending selections
        self._idx_pending_selection_origin = INVALID_IDX
        self._idx_pending_selection_start = INVALID_IDX
        self._idx_pending_selection_end = INVALID_IDX

        #
        # if we just selected a new region on a trace viz that's a
        # 'zoomer', then we will apply the zoom-in action to ourself by
        # adjusting our visible regions (bounds)
        #
        # NOTE: that we don't have to do this on a global / static trace
        # viz, because the 'zoomers' will be notified as a listener of
        # the selection change events
        #

        if self._is_zoom:

            #
            # ensure the committed selection is also reset as we are about
            # to zoom-in and should not have an active selection once done
            #

            self._idx_selection_start = INVALID_IDX
            self._idx_selection_end = INVALID_IDX

            #
            # apply the new zoom-in / viz bounds to ourself
            #
            # NOTE: because the special cell-drawing metrics / computation, set
            # bounds can 'tweak' the end value, so we want to grab it here
            #

            new_start, new_end = self.set_bounds(new_start, new_end)

        # commit the new selection for global trace visualizations
        else:
            self._idx_selection_start = new_start
            self._idx_selection_end = new_end

        # notify listeners of our selection change
        self._notify_selection_changed(new_start, new_end)

    def _get_closest_highlighted_idx(self, idx):
        """
        Return the closest idx (timestamp) to the given idx.
        """
        closest_idx = INVALID_IDX
        smallest_distace = 999999999999999999999999
        for entries in [self._idx_reads, self._idx_writes, self._idx_executions]:
            for current_idx in entries:
                distance = abs(idx - current_idx)
                if distance < smallest_distace:
                    closest_idx = current_idx
                    smallest_distace = distance
        return closest_idx

    def _breakpoints_changed(self):
        """
        The focused breakpoint has changed.
        """
        self._refresh_trace_highlights()
        self.refresh()

    def _refresh_trace_highlights(self):
        """
        Refresh trace event / highlight info from the underlying trace reader.
        """
        self._idx_reads = []
        self._idx_writes = []
        self._idx_executions = []

        reader, density = self.reader, self.density
        if not (reader and density != INVALID_DENSITY):
            return

        model = self.pctx.breakpoints.model

        # fetch executions for all breakpoints
        for bp in model.bp_exec.values():
            executions = reader.get_executions_between(bp.address, self.start_idx, self.end_idx, density)
            self._idx_executions.extend(executions)

        # fetch all memory read (only) breakpoints hits
        for bp in model.bp_read.values():
            if bp.length == 1:
                reads = reader.get_memory_reads_between(bp.address, self.start_idx, self.end_idx, density)
            else:
                reads = reader.get_memory_region_reads_between(bp.address, bp.length, self.start_idx, self.end_idx, density)
            self._idx_reads.extend(reads)

        # fetch all memory write (only) breakpoint hits
        for bp in model.bp_write.values():
            if bp.length == 1:
                writes = reader.get_memory_writes_between(bp.address, self.start_idx, self.end_idx, density)
            else:
                writes = reader.get_memory_region_writes_between(bp.address, bp.length, self.start_idx, self.end_idx, density)
            self._idx_writes.extend(writes)

        # fetch memory access for all breakpoints
        for bp in model.bp_access.values():
            if bp.length == 1:
                reads, writes = reader.get_memory_accesses_between(bp.address, self.start_idx, self.end_idx, density)
            else:
                reads, writes = reader.get_memory_region_accesses_between(bp.address, bp.length, self.start_idx, self.end_idx, density)
            self._idx_reads.extend(reads)
            self._idx_writes.extend(writes)

    def _clamp_idx(self, idx):
        """
        Clamp the given idx to the bounds of this trace view.
        """
        if idx < self.start_idx:
            return self.start_idx
        elif idx >= self.end_idx:
            return self.end_idx - 1
        return idx

    #-------------------------------------------------------------------------
    # Drawing
    #-------------------------------------------------------------------------

    def paintEvent(self, event):
        """
        Qt overload of widget painting.

        TODO/FUTURE: I was planning to make this paint by layer, and only
        re-paint dirty layers as necessary. but I think it's unecessary to
        do at this time as I don't think we're pressed for perf.
        """
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
        Draw the trace visualization of executed code.
        """

        #
        # NOTE: DO NOT REMOVE !!! Qt will CRASH if we do not explicitly delete
        # these here (dangling internal pointer to device/image otherwise?!?)
        #

        del self._painter_base

        self._image_base = QtGui.QImage(self.width(), self.height(), QtGui.QImage.Format_ARGB32)
        self._image_base.fill(self.pctx.palette.trace_bedrock)
        #self._image_base.fill(QtGui.QColor("red")) # NOTE/debug
        self._painter_base = QtGui.QPainter(self._image_base)

        # redraw instructions
        if self.cells_visible:
            self._draw_code_cells(self._painter_base)
        else:
            self._draw_code_trace(self._painter_base)

    def _draw_code_trace(self, painter):
        """
        Draw a 'zoomed out' trace visualization of executed code.
        """
        dctx = disassembler[self.pctx]
        viz_w, viz_h = self.viz_size
        viz_x, viz_y = self.viz_pos

        for i in range(viz_h):

            # convert a y pixel in the viz region to an executed address
            wid_y = viz_y + i
            idx = self._pos2idx(wid_y)

            #
            # since we can conciously set a trace visualization bounds bigger
            # than the actual underlying trace, it is possible for the trace
            # to not take up the entire available space.
            #
            # when we reach the 'end' of the trace, we obviously can stop
            # drawing any sort of landscape for it!
            #

            if idx >= self._last_trace_idx:
                break

            # get the executed/code address for the current idx that will represent this line
            address = self.reader.get_ip(idx)
            rebased_address = self.reader.analysis.rebase_pointer(address)

            # select the color for instructions that can be viewed with Tenet
            if dctx.is_mapped(rebased_address):
                painter.setPen(self.pctx.palette.trace_instruction)

            # unexplorable parts of the trace are 'greyed' out (eg, not in IDB)
            else:
                painter.setPen(self.pctx.palette.trace_unmapped)

            # paint the current line
            painter.drawLine(viz_x, wid_y, viz_w, wid_y)

    def _draw_code_cells(self, painter):
        """
        Draw a 'zoomed in', cell-based, trace visualization of executed code.
        """

        #
        # if there is no spacing between cells, that means they are going to
        # be relatively small and have shared 'cell walls' (borders)
        #
        # we attempt to maximize contrast between border and cell color, while
        # attempting to keep the tracebar color visually consistent
        #

        # compute the color to use for the borders between cells
        border_color = self.pctx.palette.trace_cell_wall
        if self._cell_spacing < 0:
            border_color = self.pctx.palette.trace_cell_wall_contrast

        # compute the color to use for the cell bodies
        if self._cell_spacing < 0:
            ratio = (self._cell_border / (self._cell_height - 1)) * 0.5
            lighten = 100 + int(ratio * 100)
            cell_color = self.pctx.palette.trace_instruction.lighter(lighten)
            #print(f"Lightened by {lighten}% (Border: {self._cell_border}, Body: {self._cell_height}")
        else:
            cell_color = self.pctx.palette.trace_instruction

        border_pen = QtGui.QPen(border_color, self._cell_border, QtCore.Qt.SolidLine)
        painter.setPen(border_pen)
        painter.setBrush(cell_color)

        viz_x, _ = self.viz_pos
        viz_w, _ = self.viz_size

        # compute cell positioning info
        x = viz_x + self._cell_border * -1
        w = viz_w + self._cell_border
        h = self._cell_height

        dctx = disassembler[self.pctx]

        # draw each cell + border
        for idx in range(self.start_idx, self._last_trace_idx):

            # get the executed/code address for the current idx that will represent this cell
            address = self.reader.get_ip(idx)
            rebased_address = self.reader.analysis.rebase_pointer(address)

            # select the color for instructions that can be viewed with Tenet
            if dctx.is_mapped(rebased_address):
                painter.setBrush(cell_color)

            # unexplorable parts of the trace are 'greyed' out (eg, not in IDB)
            else:
                painter.setBrush(self.pctx.palette.trace_unmapped)

            y = self._idx2pos(idx)
            painter.drawRect(int(x), int(y), int(w), int(h))

    def _draw_highlights(self):
        """
        Draw active event highlights (mem access, breakpoints) for the trace visualization.
        """

        #
        # NOTE: DO NOT REMOVE !!! Qt will CRASH if we do not explicitly delete
        # these here (dangling internal pointer to device/image otherwise?!?)
        #

        del self._painter_highlights

        self._image_highlights = QtGui.QImage(self.width(), self.height(), QtGui.QImage.Format_ARGB32)
        self._image_highlights.fill(QtCore.Qt.transparent)
        self._painter_highlights = QtGui.QPainter(self._image_highlights)

        if self.cells_visible:
            self._draw_highlights_cells(self._painter_highlights)
        else:
            self._draw_highlights_trace(self._painter_highlights)

    def _draw_highlights_cells(self, painter):
        """
        Draw cell-based event highlights.
        """
        viz_w, _ = self.viz_size
        viz_x, _ = self.viz_pos

        access_sets = \
        [
            (self._idx_reads, self.pctx.palette.mem_read_bg),
            (self._idx_writes, self.pctx.palette.mem_write_bg),
            (self._idx_executions, self.pctx.palette.breakpoint),
        ]

        painter.setPen(QtCore.Qt.NoPen)

        h = self._cell_height - self._cell_border

        for entries, cell_color in access_sets:
            painter.setBrush(cell_color)

            for idx in entries:

                # skip entries that fall outside the visible zoom
                if not(self.start_idx <= idx < self.end_idx):
                    continue

                # slight tweak of y because we are only drawing a highlighted
                # cell body without borders
                y = self._idx2pos(idx) + self._cell_border

                # draw cell body
                painter.drawRect(int(viz_x), int(y), int(viz_w), int(h))

    def _draw_highlights_trace(self, painter):
        """
        Draw trace-based event highlights.
        """
        viz_w, _ = self.viz_size
        viz_x, _ = self.viz_pos

        access_sets = \
        [
            (self._idx_reads, self.pctx.palette.mem_read_bg),
            (self._idx_writes, self.pctx.palette.mem_write_bg),
            (self._idx_executions, self.pctx.palette.breakpoint),
        ]

        for entries, color in access_sets:
            painter.setPen(color)

            for idx in entries:

                # skip entries that fall outside the visible zoom
                if not(self.start_idx <= idx < self.end_idx):
                    continue

                y = self._idx2pos(idx)
                painter.drawLine(viz_x, y, viz_w, y)

    def _draw_cursor(self):
        """
        Draw the user cursor / current position in the trace.
        """
        path = QtGui.QPainterPath()

        size = 13
        assert size % 2, "Cursor triangle size must be odd"

        del self._painter_cursor
        self._image_cursor = QtGui.QImage(self.width(), self.height(), QtGui.QImage.Format_ARGB32)
        self._image_cursor.fill(QtCore.Qt.transparent)
        self._painter_cursor = QtGui.QPainter(self._image_cursor)

        # compute the y coordinate / line to center the user cursor around
        cursor_y = self._idx2pos(self.reader.idx)
        draw_reader_cursor = bool(cursor_y != INVALID_IDX)

        if self.cells_visible:
            cell_y = cursor_y + self._cell_border
            cell_body_height = self._cell_height - self._cell_border
            cursor_y += self._cell_height/2

        # the top point of the triangle
        top_x = 0
        top_y = cursor_y - (size // 2) # vertically align the triangle so the tip matches the cross section

        # bottom point of the triangle
        bottom_x = top_x
        bottom_y = top_y + size - 1

        # the 'tip' of the triangle pointing into towards the center of the trace
        tip_x = top_x + (size // 2)
        tip_y = top_y + (size // 2)

        # start drawing from the 'top' of the triangle
        path.moveTo(top_x, top_y)

        # generate the triangle path / shape
        path.lineTo(bottom_x, bottom_y)
        path.lineTo(tip_x, tip_y)
        path.lineTo(top_x, top_y)

        viz_x, _ = self.viz_pos
        viz_w, _ = self.viz_size

        # draw the user cursor in cell mode
        if self.cells_visible:

            # normal fixed / current reader cursor
            self._painter_cursor.setPen(QtCore.Qt.NoPen)
            self._painter_cursor.setBrush(self.pctx.palette.trace_cursor_highlight)

            if draw_reader_cursor:
                self._painter_cursor.drawRect(int(viz_x), int(cell_y), int(viz_w), int(cell_body_height))

            # cursor hover highlighting an event
            if self._hovered_idx != INVALID_IDX:
                hovered_y = self._idx2pos(self._hovered_idx)
                hovered_cell_y = hovered_y + self._cell_border
                self._painter_cursor.drawRect(int(viz_x), int(hovered_cell_y), int(viz_w), int(cell_body_height))

        # draw the user cursor in dense/landscape mode
        else:
            self._painter_cursor.setPen(self._pen_cursor)

            # normal fixed / current reader cursor
            if draw_reader_cursor:
                self._painter_cursor.drawLine(viz_x, cursor_y, viz_w, cursor_y)

            # cursor hover highlighting an event
            if self._hovered_idx != INVALID_IDX:
                hovered_y = self._idx2pos(self._hovered_idx)
                self._painter_cursor.drawLine(viz_x, hovered_y, viz_w, hovered_y)

        if not draw_reader_cursor:
            return

        # paint the defined triangle
        self._painter_cursor.setPen(self.pctx.palette.trace_cursor_border)
        self._painter_cursor.setBrush(self.pctx.palette.trace_cursor)
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

        viz_w, viz_h = self.viz_size
        self._image_selection = QtGui.QImage(self.width(), self.height(), QtGui.QImage.Format_ARGB32)
        self._image_selection.fill(QtCore.Qt.transparent)
        self._painter_selection = QtGui.QPainter(self._image_selection)

        # active / on-going selection event
        if self._idx_pending_selection_start != INVALID_IDX:
            start_idx = self._idx_pending_selection_start
            end_idx = self._idx_pending_selection_end

        # fixed / committed selection
        elif self._idx_selection_start != INVALID_IDX:
            start_idx = self._idx_selection_start
            end_idx = self._idx_selection_end

        # no region selection, nothing to do...
        else:
            return

        start_idx = self._clamp_idx(start_idx)
        end_idx = self._clamp_idx(end_idx)

        # nothing to draw
        if start_idx == end_idx:
            return

        start_y = self._idx2pos(start_idx)
        end_y = self._idx2pos(end_idx)

        self._painter_selection.setBrush(self._brush_selection)
        self._painter_selection.setPen(self._pen_selection)

        # TODO/FUTURE: real border math
        viz_x, viz_y = self.viz_pos

        x = viz_x
        y = start_y
        w = viz_w
        h = end_y - start_y

        # draw the screen door / selection rect
        self._painter_selection.drawRect(int(x), int(y), int(w), int(h))

    def _draw_border(self):
        """
        Draw the border around the trace timeline.
        """
        wid_w, wid_h = self.width(), self.height()

        #
        # NOTE: DO NOT REMOVE !!! Qt will CRASH if we do not explicitly delete
        # these here (dangling internal pointer to device/image otherwise?!?)
        #

        del self._painter_border

        self._image_border = QtGui.QImage(wid_w, wid_h, QtGui.QImage.Format_ARGB32)
        self._image_border.fill(QtCore.Qt.transparent)
        self._painter_border = QtGui.QPainter(self._image_border)

        color = self.pctx.palette.trace_border
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
# Trace View
#-----------------------------------------------------------------------------

class TraceView(QtWidgets.QWidget):

    def __init__(self, pctx, parent=None):
        super(TraceView, self).__init__(parent)
        self.pctx = pctx
        self._init_ui()

    def _init_ui(self):
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
        self.trace_local = TraceBar(self.pctx, zoom=True)
        self.trace_global = TraceBar(self.pctx)

        # connect the local view to follow the global selection
        self.trace_global.selection_changed(self.trace_local._zoom_selection_changed)
        self.trace_local.selection_changed(self.trace_global._global_selection_changed)

        # connect other signals
        self.pctx.breakpoints.model.breakpoints_changed(self.trace_global._breakpoints_changed)
        self.pctx.breakpoints.model.breakpoints_changed(self.trace_local._breakpoints_changed)

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
        Initialize the right click context menu actions.
        """
        self._menu = QtWidgets.QMenu()

        # create actions to show in the context menu
        self._action_clear = self._menu.addAction("Clear all breakpoints")
        self._menu.addSeparator()
        self._action_load = self._menu.addAction("Load new trace")
        self._action_close = self._menu.addAction("Close trace")

        # install the right click context menu
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._ctx_menu_handler)

    #--------------------------------------------------------------------------
    # Signals
    #--------------------------------------------------------------------------

    def _ctx_menu_handler(self, position):
        """
        Handle a right click event (populate/show context menu).
        """
        action = self._menu.exec_(self.mapToGlobal(position))
        if action == self._action_load:
            self.pctx.interactive_load_trace(True)
        elif action == self._action_close:
            self.pctx.close_trace()
        elif action == self._action_clear:
            self.pctx.breakpoints.clear_breakpoints()

    def update_from_model(self):
        for bar in self.model.tracebars.values()[::-1]:
            self.hbox.addWidget(bar)

        # this will insert the children (tracebars) and apply spacing as appropriate
        self.bar_container.setLayout(self.hbox)

#-----------------------------------------------------------------------------
# Dockable Trace Visualization
#-----------------------------------------------------------------------------

class TraceDock(QtWidgets.QToolBar):
    """
    A Qt 'Toolbar' to house the TraceBar visualizations.

    We use a Toolbar explicitly because they are given unique docking regions
    around the QMainWindow in Qt-based applications. This allows us to pin
    the visualizations to areas where they will not be dist
    """
    def __init__(self, pctx, parent=None):
        super(TraceDock, self).__init__(parent)
        self.pctx = pctx
        self.view = TraceView(pctx, self)
        self.setMovable(False)
        self.setContentsMargins(0, 0, 0, 0)
        self.addWidget(self.view)

    def attach_reader(self, reader):
        self.view.attach_reader(reader)

    def detach_reader(self):
        self.view.detach_reader()