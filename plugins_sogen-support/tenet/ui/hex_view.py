import struct

from tenet.types import *
from tenet.util.qt import *

INVALID_ADDRESS = -1

class HexView(QtWidgets.QAbstractScrollArea):
    """
    A Qt based hex / memory viewer.

    Adapted from:
     - https://github.com/virinext/QHexView

    """

    def __init__(self, controller, model, parent=None):
        super(HexView, self).__init__(parent)
        self.controller = controller
        self.model = model
        self._palette = controller.pctx.palette

        self.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)

        font = QtGui.QFont("Courier", pointSize=normalize_font(9))
        font.setStyleHint(QtGui.QFont.TypeWriter)
        self.setFont(font)
        self.setMouseTracking(True)

        fm = QtGui.QFontMetricsF(font)
        self._char_width = fm.width('9')
        self._char_height = int(fm.tightBoundingRect('9').height() * 1.75)
        self._char_descent = self._char_height - fm.descent()*0.75

        self._click_timer = QtCore.QTimer(self)
        self._click_timer.setSingleShot(True)
        self._click_timer.timeout.connect(self._commit_click)

        self._double_click_timer = QtCore.QTimer(self)
        self._double_click_timer.setSingleShot(True)

        self.hovered_address = INVALID_ADDRESS

        self._selection_start = INVALID_ADDRESS
        self._selection_end = INVALID_ADDRESS

        self._pending_selection_origin = INVALID_ADDRESS
        self._pending_selection_start = INVALID_ADDRESS
        self._pending_selection_end = INVALID_ADDRESS

        self._ignore_navigation = False

        self._init_ctx_menu()

    def _init_ctx_menu(self):
        """
        Initialize the right click context menu actions.
        """

        # create actions to show in the context menu
        self._action_copy = QtWidgets.QAction("Copy", None)
        self._action_clear = QtWidgets.QAction("Clear mem breakpoints", None)
        self._action_follow_in_dump = QtWidgets.QAction("Follow in dump", None)

        bp_types = \
        [
            ("Read", BreakpointType.READ),
            ("Write", BreakpointType.WRITE),
            ("Access", BreakpointType.ACCESS)
        ]

        #
        # break on action group
        #

        self._action_break = {}

        for name, bp_type in bp_types:
            action = QtWidgets.QAction(name, None)
            action.setCheckable(True)
            self._action_break[action] = bp_type

        self._break_menu = QtWidgets.QMenu("Break on...")
        self._break_menu.addActions(self._action_break)

        #
        # goto action groups
        #

        self._action_first = {}
        self._action_prev = {}
        self._action_next = {}
        self._action_final = {}

        for name, bp_type in bp_types:
            self._action_prev[QtWidgets.QAction(name, None)] = bp_type
            self._action_next[QtWidgets.QAction(name, None)] = bp_type
            self._action_first[QtWidgets.QAction(name, None)] = bp_type
            self._action_final[QtWidgets.QAction(name, None)] = bp_type

        self._goto_menus = \
        [
            (QtWidgets.QMenu("Go to first..."), self._action_first),
            (QtWidgets.QMenu("Go to previous..."), self._action_prev),
            (QtWidgets.QMenu("Go to next..."), self._action_next),
            (QtWidgets.QMenu("Go to final..."), self._action_final),
        ]

        for submenu, actions in self._goto_menus:
            submenu.addActions(actions)

        # install the right click context menu
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._ctx_menu_handler)

    #-------------------------------------------------------------------------
    # Properties
    #-------------------------------------------------------------------------

    @property
    def num_lines_visible(self):
        """
        Return the number of lines visible in the hex view.
        """
        area_size = self.viewport().size()
        first_line_idx = self.verticalScrollBar().value()
        last_line_idx = (first_line_idx + area_size.height() // self._char_height) + 1
        lines_visible = last_line_idx - first_line_idx
        return lines_visible

    @property
    def num_bytes_visible(self):
        """
        Return the number of bytes visible in the hex view.
        """
        return self.model.num_bytes_per_line * self.num_lines_visible

    @property
    def selection_size(self):
        """
        Return the number of bytes selected in the hex view.
        """
        if self._selection_end == self._selection_start == INVALID_ADDRESS:
            return 0
        return self._selection_end - self._selection_start

    @property
    def hovered_breakpoint(self):
        """
        Return the hovered breakpoint.
        """
        if self.hovered_address == INVALID_ADDRESS:
            return None

        for bp in self.model.memory_breakpoints:
            if bp.address <= self.hovered_address < bp.address + bp.length:
                return bp

        return None

    #-------------------------------------------------------------------------
    # Internal
    #-------------------------------------------------------------------------

    def refresh(self):
        """
        Refresh the hex view.
        """
        self._refresh_painting_metrics()
        self.viewport().update()

    def _refresh_painting_metrics(self):
        """
        Refresh any metrics and calculations required to paint the widget.
        """

        # 2 chars per byte of data, eg '00'
        self._chars_in_line  = self.model.num_bytes_per_line * 2

        # add 1 char for each space between elements (bytes, dwords, qwords...)
        self._chars_in_line += (self.model.num_bytes_per_line // HEX_TYPE_WIDTH[self.model.hex_format])

        # the x position to draw the text address (left side of view)
        self._pos_addr = self._char_width // 2

        # the width of the column, 2 nibbles (chars) per byte of a pointer
        # -- +1 for padding, (eg, 1/2 char on each side)
        self._width_addr = (self.model.pointer_size * 2 + 1) * self._char_width

        # the x position and width of the hex bytes region (center section of view)
        self._pos_hex = self._width_addr + self._char_width
        self._width_hex = self._chars_in_line * self._char_width

        # the x position and width of the auxillary region (right section of view)
        self._pos_aux = self._pos_hex + self._width_hex
        self._width_aux = (self.model.num_bytes_per_line * self._char_width) + self._char_width * 2

        # enforce a minimum view width, to ensure all text stays visible
        self.setMinimumWidth(int(self._pos_aux + self._width_aux))

    def full_size(self):
        """
        TODO
        """
        if not self.model.data:
            return QtCore.QSize(0, 0)

        width = int(self._pos_aux + (self.model.num_bytes_per_line * self._char_width))
        height = len(self.model.data) // self.model.num_bytes_per_line
        if len(self.model.data) % self.model.num_bytes_per_line:
            height += 1

        height *= self._char_height

        return QtCore.QSize(width, height)

    def point_to_index(self, position):
        """
        Convert a QPoint (x, y) on the hex view window to a byte index.

        TODO/XXX: ugh this whole function / selection logic needs to be
        rewritten... it's actually impossible to follow.
        """
        padding = self._char_width // 2

        if position.x() < (self._pos_hex - padding):
            return -1

        cutoff = self._pos_hex + self._width_hex - padding
        #print(f"Position: {position} Cutoff: {cutoff} Pos Hex: {self._pos_hex} Width Hex: {self._width_hex} Padding: {padding}")
        if position.x() >= cutoff:
            return -1

        # convert 'gloabl' x in the viewport, to an x that is 'relative' to the hex area
        hex_x = (position.x() - self._pos_hex) + padding
        #print("- Hex x", hex_x)

        # the number of items (eg, bytes, qwords) per line
        num_items = self.model.num_bytes_per_line // HEX_TYPE_WIDTH[self.model.hex_format]
        #print("- Num items", num_items)

        # compute the pixel width each rendered item on the line takes up
        item_width = (self._char_width * 2) * HEX_TYPE_WIDTH[self.model.hex_format]
        item_width_padded = item_width + self._char_width
        #print("- Item Width", item_width)
        #print("- Item Width Padded", item_width_padded)

        # compute the item index on a line (the x-axis) that the point falls within
        item_index = int(hex_x // item_width_padded)
        #print("- Item Index", item_index)

        # compute which byte is hovered in the item
        if self.model.hex_format != HexType.BYTE:

            item_base_x = item_index * item_width_padded + (self._char_width // 2)
            item_byte_x = hex_x - item_base_x
            item_byte_index = int(item_byte_x // (self._char_width * 2))

            # XXX: I give up, kludge to account for math errors
            if item_byte_index < 0:
                item_byte_index = 0
            elif item_byte_index >= self.model.num_bytes_per_line:
                item_byte_index = self.model.num_bytes_per_line - 1

            #print("- Item Byte X", item_byte_x)
            #print("- Item Byte Index", item_byte_index)

            item_byte_index = (HEX_TYPE_WIDTH[self.model.hex_format] - 1) - item_byte_index
            byte_x = item_index * HEX_TYPE_WIDTH[self.model.hex_format] + item_byte_index

        else:
            byte_x = item_index * HEX_TYPE_WIDTH[self.model.hex_format]

        # compute the line number (the y-axis) that the point falls within
        byte_y = position.y() // self._char_height
        #print("- Byte (X, Y)", byte_x, byte_y)

        # compute the final byte index from the start address in the window
        byte_index = (byte_y * self.model.num_bytes_per_line) + byte_x
        #print("- Byte Index", byte_index)

        return byte_index

    def point_to_address(self, position):
        """
        Convert a QPoint (x, y) on the hex view window to an address.
        """
        byte_index = self.point_to_index(position)
        if byte_index == -1:
            return INVALID_ADDRESS

        byte_address = self.model.address + byte_index
        return byte_address

    def point_to_breakpoint(self, position):
        """
        Convert a QPoint (x, y) on the hex view window to a breakpoint.
        """
        byte_address = self.point_to_address(position)
        if byte_address == INVALID_ADDRESS:
            return None

        for bp in self.model.memory_breakpoints:
            if bp.address <= byte_address < bp.address + bp.length:
                return bp

        return None

    def reset_selection(self):
        """
        Clear the stored user memory selection.
        """
        self._pending_selection_origin = INVALID_ADDRESS
        self._pending_selection_start = INVALID_ADDRESS
        self._pending_selection_end = INVALID_ADDRESS
        self._selection_start = INVALID_ADDRESS
        self._selection_end = INVALID_ADDRESS

    def _update_selection(self, position):
        """
        Set the user memory selection.
        """
        address = self.point_to_address(position)
        if address == INVALID_ADDRESS:
            return

        if address >= self._pending_selection_origin:
            self._pending_selection_end = address + 1
            self._pending_selection_start = self._pending_selection_origin
        else:
            self._pending_selection_start = address
            self._pending_selection_end = self._pending_selection_origin + 1

    def _commit_click(self):
        """
        Accept a click event.
        """
        self._selection_start = self._pending_selection_start
        self._selection_end = self._pending_selection_end

        self._pending_selection_origin = INVALID_ADDRESS
        self._pending_selection_start = INVALID_ADDRESS
        self._pending_selection_end = INVALID_ADDRESS

        self.viewport().update()

    def _commit_selection(self):
        """
        Accept a selection event.
        """
        self._selection_start = self._pending_selection_start
        self._selection_end = self._pending_selection_end

        self._pending_selection_origin = INVALID_ADDRESS
        self._pending_selection_start = INVALID_ADDRESS
        self._pending_selection_end = INVALID_ADDRESS

        # notify listeners of our selection change
        #self._notify_selection_changed(new_start, new_end)
        self.viewport().update()

    #--------------------------------------------------------------------------
    # Signals
    #--------------------------------------------------------------------------

    def _ctx_menu_handler(self, position):
        """
        Handle a right click event (populate/show context menu).
        """
        menu = QtWidgets.QMenu()

        ctx_breakpoint = self.point_to_breakpoint(position)
        ctx_address = self.point_to_address(position)
        ctx_type = BreakpointType.NONE

        #
        # determine the selection that the action will execute across
        #

        if self._selection_start <= ctx_address < self._selection_end:
            selected_address = self._selection_start
            selected_length = self.selection_size

        elif ctx_breakpoint:
            selected_address = ctx_breakpoint.address
            selected_length = ctx_breakpoint.length
            ctx_type = ctx_breakpoint.type

        else:
            selected_address = INVALID_ADDRESS
            selected_length = 0

        #
        # populate the popup menu
        #

        # show the 'copy text' option if the user has a region selected
        if selected_length > 1 and ctx_type == BreakpointType.NONE:
            menu.addAction(self._action_copy)

        # only show the 'follow in dump' if the controller supports it
        if hasattr(self.controller, "follow_in_dump"):
            menu.addAction(self._action_follow_in_dump)

        menu.addSeparator()

        # show the break option only if there's a selection or breakpoint
        if selected_length > 0:
            menu.addMenu(self._break_menu)
            menu.addSeparator()

        for action, access_type in self._action_break.items():
            action.setChecked(ctx_type == access_type)

        if selected_length > 0:

            # add the goto groups
            for submenu, _ in self._goto_menus:
                menu.addMenu(submenu)

        # show the 'clear breakpoints' action
        menu.addSeparator()
        menu.addAction(self._action_clear)

        #
        # show the right click context menu
        #

        action = menu.exec_(self.mapToGlobal(position))
        if not action:
            return

        #
        # execute the action selected by the suer in the right click menu
        #

        if action == self._action_copy:
            self.controller.copy_selection(self._selection_start, self._selection_end)
            return

        elif action == self._action_follow_in_dump:
            self.controller.follow_in_dump(self._selection_start)
            return

        elif action == self._action_clear:
            self.controller.pctx.breakpoints.clear_memory_breakpoints()
            return

        # TODO: this is some of the shadiest/laziest code i've ever written
        try:
            selected_type = getattr(BreakpointType, action.text().upper())
        except:
            pass

        if action in self._action_first:
            self.controller.reader.seek_to_first(selected_address, selected_type, selected_length)
        elif action in self._action_prev:
            self.controller.reader.seek_to_prev(selected_address, selected_type, selected_length)
        elif action in self._action_next:
            self.controller.reader.seek_to_next(selected_address, selected_type, selected_length)
        elif action in self._action_final:
            self.controller.reader.seek_to_final(selected_address, selected_type, selected_length)
        elif action in self._action_break:
            self.controller.pin_memory(selected_address, selected_type, selected_length)
            self.reset_selection()

    #----------------------------------------------------------------------
    # Qt Overloads
    #----------------------------------------------------------------------

    def mouseDoubleClickEvent(self, event):
        """
        Qt overload to capture mouse double-click events.
        """
        self._click_timer.stop()

        #
        # if the double click fell within an active selection, we should
        # consume the event as the user setting a region breakpoint
        #

        if self._selection_start <= self._pending_selection_start < self._selection_end:
            address = self._selection_start
            size = self.selection_size
        else:
            address = self.point_to_address(event.pos())
            size = 1

        self.controller.pin_memory(address, length=size)
        self.reset_selection()
        event.accept()

        self.viewport().update()
        self._double_click_timer.start(100)

    def mouseMoveEvent(self, event):
        """
        Qt overload to capture mouse movement events.
        """
        mouse_position = event.pos()

        # update the hovered address
        self.hovered_address = self.point_to_address(mouse_position)

        # mouse moving while holding left button
        if event.buttons() == QtCore.Qt.MouseButton.LeftButton:
            self._update_selection(mouse_position)

            #
            # if the user is actively selecting bytes and has selected more
            # than one byte, we should clear any existing selection. this will
            # make it so the new ongoing 'pending' selection will get drawn
            #

            if (self._pending_selection_end - self._pending_selection_start) > 1:
                self._selection_start = INVALID_ADDRESS
                self._selection_end = INVALID_ADDRESS

            self.viewport().update()
            return

    def mousePressEvent(self, event):
        """
        Qt overload to capture mouse button presses.
        """
        if self._double_click_timer.isActive():
            return

        if event.button() == QtCore.Qt.LeftButton:

            byte_address = self.point_to_address(event.pos())

            if not(self._selection_start <= byte_address < self._selection_end):
                self.reset_selection()

            self._pending_selection_origin = byte_address
            self._pending_selection_start = byte_address
            self._pending_selection_end = (byte_address + 1) if byte_address != INVALID_ADDRESS else INVALID_ADDRESS

        self.viewport().update()

    def mouseReleaseEvent(self, event):
        """
        Qt overload to capture mouse button releases.
        """
        if self._double_click_timer.isActive():
            return

        # handle a right click
        if event.button() == QtCore.Qt.RightButton:

            # get the address of the byte that was right clicked
            byte_address = self.point_to_address(event.pos())
            if byte_address == INVALID_ADDRESS:
                return

            # the right clicked fell within the current selection
            if self._selection_start <= byte_address < self._selection_end:
                return

            # the right click fell within an existing breakpoint
            bp = self.hovered_breakpoint
            if bp and (bp.address <= byte_address < bp.address + bp.length):
                return

            #
            # if the right click did not fall within any known selection / poi
            # we should consume it and set the current cursor selection to it
            #

            self._pending_selection_start = byte_address
            self._pending_selection_end = byte_address + 1
            self._commit_click()
            return

        if self._pending_selection_origin == INVALID_ADDRESS:
            return

        # if the mouse press & release was on a single byte, it's a click
        if (self._pending_selection_end - self._pending_selection_start) == 1:

            #
            # if the click was within a selected region, defer acting on it
            # for 500ms to see if a double click event occurs
            #

            if self._selection_start <= self._pending_selection_start < self._selection_end:
                self._click_timer.start(200)
                return
            else:
                self._commit_click()

        # a range was selected, so accept/commit it
        else:
            self._commit_selection()

    def keyPressEvent(self, e):
        """
        Qt overload to capture key press events.
        """
        if e.key() == QtCore.Qt.Key_G:
            import ida_kernwin, ida_idaapi
            address = ida_kernwin.ask_addr(self.model.address, "Jump to address in memory")
            if address != None and address != ida_idaapi.BADADDR:
                self.controller.navigate(address)
            e.accept()
        return super(HexView, self).keyPressEvent(e)

    def wheelEvent(self, event):
        """
        Qt overload to capture wheel events.
        """

        #
        # first, we will attempt special handling of the case where a user
        # 'scrolls' up or down when hovering their cursor over a byte they
        # have selected...
        #

        # compute the address of the hovered byte (if there is one...)
        byte_address = self.point_to_address(event.pos())

        for bp in self.model.memory_breakpoints:

            # skip this breakpoint if the current byte does not fall within its range
            if not(bp.address <= byte_address < bp.address + bp.length):
                continue

            #
            # XXX: bit of a hack, but it seems like the easiest way to prevent
            # the stack views from 'navigating' when you're hovering / scrolling
            # through memory accesses (see _idx_changed in stack.py)
            #

            self._ignore_navigation = True

            #
            # if a region is selected with an 'access' breakpoint on it,
            # use the start address of the selected region instead for
            # the region-based seeks
            #

            # scrolled 'up'
            if event.angleDelta().y() > 0:
                self.controller.reader.seek_to_prev(bp.address, bp.type, bp.length)

            # scrolled 'down'
            elif event.angleDelta().y() < 0:
                self.controller.reader.seek_to_next(bp.address, bp.type, bp.length)

            # restore navigation listening
            self._ignore_navigation = False

            # consume the event
            event.accept()
            return

        #
        # normal 'scroll' on the hex window.. scroll up or down into new
        # regions of memory...
        #

        if event.angleDelta().y() > 0:
            self.controller.navigate(self.model.address - self.model.num_bytes_per_line)

        elif event.angleDelta().y() < 0:
            self.controller.navigate(self.model.address + self.model.num_bytes_per_line)

        event.accept()

    def resizeEvent(self, event):
        """
        Qt overload to capture resize events for the widget.
        """
        super(HexView, self).resizeEvent(event)
        self._refresh_painting_metrics()
        self.controller.set_data_size(self.num_bytes_visible)

    #-------------------------------------------------------------------------
    # Painting
    #-------------------------------------------------------------------------

    def paintEvent(self, event):
        """
        Qt overload of widget painting.
        """
        if not self.model.data:
            return

        painter = QtGui.QPainter(self.viewport())

        # paint background of entire scroll area
        painter.fillRect(event.rect(), self._palette.hex_data_bg)

        # paint address area background
        address_area_rect = QtCore.QRect(0, event.rect().top(), int(self._width_addr), self.height())
        painter.fillRect(address_area_rect, self._palette.hex_address_bg)

        # paint line between address area and hex area
        painter.setPen(self._palette.hex_separator)
        painter.drawLine(int(self._width_addr), event.rect().top(), int(self._width_addr), self.height())

        # paint line between hex area and auxillary area
        line_pos = self._pos_aux
        painter.setPen(self._palette.hex_separator)
        painter.drawLine(int(line_pos), event.rect().top(), int(line_pos), self.height())

        for line_idx in range(0, self.num_lines_visible):
            self._paint_line(painter, line_idx)

    def _paint_line(self, painter, line_idx):
        """
        Paint one line of hex.
        """
        self._brush_default = painter.brush()
        self._brush_selected = QtGui.QBrush(self._palette.standard_selection_bg)
        self._brush_navigation = QtGui.QBrush(self._palette.navigation_selection_fg)

        # the pixel position to start painting from
        x, y = self._pos_hex, (line_idx + 1) * self._char_height

        # clamp the address from 0 to 0xFFFFFFFFFFFFFFFF
        address = self.model.address + (line_idx * self.model.num_bytes_per_line)
        if address > 0xFFFFFFFFFFFFFFFF:
            address = 0xFFFFFFFFFFFFFFFF

        address_color = self._palette.hex_address_fg
        if address < self.model.fade_address:
            address_color = self._palette.hex_text_faded_fg

        painter.setPen(address_color)

        # draw the address text
        pack_len = self.model.pointer_size
        address_fmt = '%016X' if pack_len == 8 else '%08X'
        address_text = address_fmt % address
        painter.drawText(int(self._pos_addr), y, address_text)

        self._default_color = self._palette.hex_text_fg
        if address < self.model.fade_address:
            self._default_color = self._palette.hex_text_faded_fg

        painter.setPen(self._default_color)

        byte_base_idx = line_idx * self.model.num_bytes_per_line
        byte_idx = byte_base_idx
        stop_idx = min(len(self.model.data), byte_base_idx + self.model.num_bytes_per_line)

        # paint each element on the line, up until the end of the line, or buffer
        while byte_idx < stop_idx:
            byte_idx, x, y = self._paint_hex_item(painter, byte_idx, stop_idx, x, y)

        assert byte_idx == stop_idx

        #
        # paint 'readable' ASCII
        #

        byte_idx = byte_base_idx
        x_pos_aux = self._pos_aux + self._char_width

        if self.model.aux_format == AuxType.ASCII:

            for i in range(byte_base_idx, stop_idx):

                if self.model.mask[i]:
                    painter.setPen(self._default_color)
                else:
                    painter.setPen(self._palette.hex_text_faded_fg)

                ch = self.model.data[i]
                if ((ch < 0x20) or (ch > 0x7e)):
                    ch = '.'
                else:
                    ch = chr(ch)

                painter.drawText(int(x_pos_aux), y, ch)
                x_pos_aux += self._char_width

    def _paint_hex_item(self, painter, byte_idx, stop_idx, x, y):
        """
        Paint a single hex item.
        """

        # draw single bytes
        if self.model.hex_format == HexType.BYTE:
            return self._paint_byte(painter, byte_idx, x, y)

        # draw dwords
        elif self.model.hex_format == HexType.DWORD:
            return self._paint_dword(painter, byte_idx, x, y)

        # draw qwords
        elif self.model.hex_format == HexType.QWORD:
            return self._paint_qword(painter, byte_idx, x, y)

        # identify and draw pointers
        elif self.model.hex_format == HexType.MAGIC:
            return self._paint_magic(painter, byte_idx, stop_idx, x, y)

        raise NotImplementedError("Unknown HexType format! %s" % self.model.hex_format)

        #return (byte_idx, x, y)

    def _paint_byte(self, painter, byte_idx, x, y):
        """
        Paint a BYTE at the current position.
        """
        self._paint_text(painter, byte_idx, 1, x, y)
        x += (2 + 1) * self._char_width

        return (byte_idx + 1, x, y)

    def _paint_dword(self, painter, byte_idx, x, y):
        """
        Paint a DWORD at the current position.
        """
        backwards_idx = byte_idx - 1

        for i in range(backwards_idx + 4, backwards_idx, -1):
            self._paint_text(painter, i, 0, x, y)
            x += self._char_width * 2

        return (byte_idx + 4, x, y)

    def _paint_qword(self, painter, byte_idx, x, y):
        """
        Paint a QWORD at the current position.
        """
        backwards_idx = byte_idx - 1

        for i in range(backwards_idx + 8, backwards_idx, -1):
            self._paint_text(painter, i, 0, x, y)
            x += self._char_width * 2

        return (byte_idx + 8, x, y)

    def _paint_text(self, painter, byte_idx, padding, x, y):

        if self.model.mask[byte_idx]:
            fg_color = self._default_color
            text = "%02X" % self.model.data[byte_idx]
        else:
            fg_color = self._palette.hex_text_faded_fg
            text = "??"

        #
        # paint text selection background color / highlight
        #

        x_bg = x - (self._char_width // 2) * padding
        y_bg = y - self._char_descent

        width = self._char_width * (len(text) + padding)
        height = self._char_height

        bg_color = None
        border_color = None

        # compute the address of the byte we're drawing
        byte_address = self.model.address + byte_idx

        # initialize selection start / end vars
        start_address = INVALID_ADDRESS
        end_address = INVALID_ADDRESS

        # fixed / committed selection
        if self._selection_start != INVALID_ADDRESS:
            start_address = self._selection_start
            end_address = self._selection_end

        # active / on-going selection event
        elif self._pending_selection_start != INVALID_ADDRESS:
            start_address = self._pending_selection_start
            end_address = self._pending_selection_end

        # a byte that falls within the user selection
        if start_address <= byte_address < end_address:
            bg_color = self._palette.standard_selection_bg

            # set the text color for selected text
            if self.model.mask[byte_idx]:
                fg_color = self._palette.standard_selection_fg
            else:
                fg_color = self._palette.standard_selection_faded_fg

        # a byte that was written
        elif byte_address in self.model.delta.mem_writes:
            bg_color = self._palette.mem_write_bg
            fg_color = self._palette.mem_write_fg

        # a byte that was read
        elif byte_address in self.model.delta.mem_reads:
            bg_color = self._palette.mem_read_bg
            fg_color = self._palette.mem_read_fg

        # a breakpoint byte
        for bp in self.model.memory_breakpoints:

            # skip this breakpoint if the current byte does not fall within its range
            if not(bp.address <= byte_address < bp.address + bp.length):
                continue

            #
            # if the breakpoint is a single byte, ensure it will always have a
            # border around it, regardless of if it is selected, read, or
            # written.
            #
            # this makes it easy to tell when you have selected or are hovering
            # an active 'hot' byte / breakpoint that can be scrolled over to
            # seek between accesses
            #

            if bp.length == 1:
                border_color = self._palette.navigation_selection_bg

            #
            # if the background color for this byte has already been
            # specified, that means a read/write probably occured to it so
            # we should prioritize those colors OVER the breakpoint coloring
            #

            if bg_color:
                break

            #
            # if the byte wasn't read/written/selected, we are free to color
            # it red, as it falls within an active breakpoint region
            #

            bg_color = self._palette.navigation_selection_bg

            # if the byte value is know (versus '??'), set its text color
            if self.model.mask[byte_idx]:
                fg_color = self._palette.navigation_selection_fg
            else:
                fg_color = self._palette.navigation_selection_faded_fg

            #
            # no need to keep searching through breakpoints once the byte has
            # been colored! break and go paint the byte...
            #

            break

        # the byte is highlighted in some fashion, paint it now
        if bg_color:

            if border_color:
                pen = QtGui.QPen(border_color, 2)
                pen.setJoinStyle(QtCore.Qt.MiterJoin)
                painter.setPen(pen)
                x_bg += 1
                y_bg += 1
                width -= 2
                height -= 2

            else:
                painter.setPen(QtCore.Qt.NoPen)

            painter.setBrush(bg_color)
            painter.drawRect(int(x_bg), int(y_bg), int(width), int(height))

        painter.setPen(fg_color)

        #
        # paint text
        #

        painter.drawText(int(x), y, text)

    def _paint_magic(self, painter, byte_idx, stop_idx, x, y):
        """
        Perform magic painting at the current position.

        This will essentially try to identify pointers while painting, and
        format them as appropriate.

        TODO: this needs to be updated to be truly pointer size agnostic
        """

        # not enough bytes left to identify / paint a pointer from the data
        if byte_idx + self.model.pointer_size > stop_idx:
            return self._paint_byte(painter, byte_idx, x, y)

        # ensure that all the bytes for the 'pointer' to analyze are known
        pack_len = self.model.pointer_size
        pack_fmt = 'Q' if pack_len == 8 else 'I'
        mask = struct.unpack(pack_fmt, self.model.mask[byte_idx:byte_idx+pack_len])[0]
        if mask != 0xFFFFFFFFFFFFFFFF:
            return self._paint_byte(painter, byte_idx, x, y)

        # read and analyze the value to determine if it is a pointer
        value = struct.unpack(pack_fmt, self.model.data[byte_idx:byte_idx+pack_len])[0]
        if not self.controller.pctx.is_pointer(value):
            return self._paint_byte(painter, byte_idx, x, y)

        #
        # it seems like a pointer, let's draw one!
        #

        # compute how many characters would have normally filled this space
        # if inidividual bytes were printed instead...
        num_chars = 3 * self.model.pointer_size

        # draw the pointer
        pointer_str = ("0x%08X " % value).rjust(num_chars)
        painter.drawText(int(x), y, pointer_str)
        x += num_chars * self._char_width

        return (byte_idx + self.model.pointer_size, x, y)
