import struct

from tenet.types import *
from tenet.util.qt import *

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

        font = QtGui.QFont("Courier", pointSize=normalize_font(9))
        font.setStyleHint(QtGui.QFont.TypeWriter)
        self.setFont(font)

        fm = QtGui.QFontMetricsF(font)
        self._char_width = fm.width('9')
        self._char_height = int(fm.tightBoundingRect('9').height() * 1.75)
        self._char_descent = self._char_height - fm.descent()*0.75

        self._select_init = -1
        self._select_begin = -1
        self._select_end = -1
        self._region_access = False

        self.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)

        self._init_ctx_menu()

    def _init_ctx_menu(self):
        """
        TODO
        """

        # create actions to show in the context menu
        self._action_copy = QtWidgets.QAction("Copy", None)
        self._action_find_accesses = QtWidgets.QAction("Find accesses", None)
        self._action_follow_in_dump = QtWidgets.QAction("Follow in Dump", None)

        # goto action groups
        self._action_first = {}
        self._action_prev = {}
        self._action_next = {}
        self._action_final = {}

        bp_types = \
        [
            ("Read", BreakpointType.READ),
            ("Write", BreakpointType.WRITE),
            ("Access", BreakpointType.ACCESS)
        ]

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

    def _ctx_menu_handler(self, position):
        menu = QtWidgets.QMenu()

        #
        # populate the popup menu 
        #

        # populate these items only if the user has selected one or more bytes
        if self.selection_size > 1:
            menu.addAction(self._action_copy)
            menu.addAction(self._action_find_accesses)

        # populate these items when no bytes are selected
        else:
            if hasattr(self.controller, "follow_in_dump"):
                menu.addAction(self._action_follow_in_dump)

        # add the breakpoint / goto groups
        for submenu, _ in self._goto_menus:
            menu.addMenu(submenu)

        #
        # show the right click context menu
        #

        action = menu.exec_(self.mapToGlobal(position))

        #
        # execute the action selected by the suer in the right click menu
        #

        if action == self._action_find_accesses:
            byte_address = self._select_begin
            self._region_access = True
            self.controller.focus_region_access(byte_address, self.selection_size)
            self.viewport().update()

        elif action == self._action_follow_in_dump:
            self.controller.follow_in_dump(self._select_begin)

        elif action == self._action_copy:
            self.controller.copy_selection(self._select_begin, self._select_end)

        else:

            # TODO: this is some of the shadiest/laziest code i've ever written
            try:
                bp_type = getattr(BreakpointType, action.text().upper())
            except:
                pass

            address = self._select_begin
            length = self.selection_size

            if action in self._action_first:
                self.controller.reader.seek_to_first(address, bp_type, length)
            elif action in self._action_prev:
                self.controller.reader.seek_to_prev(address, bp_type, length)
            elif action in self._action_next:
                self.controller.reader.seek_to_next(address, bp_type, length)
            elif action in self._action_final:
                self.controller.reader.seek_to_final(address, bp_type, length)

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
        if self._select_end == self._select_begin == -1:
            return 0
        return self._select_end - self._select_begin

    #-------------------------------------------------------------------------
    # Internal
    #-------------------------------------------------------------------------

    def refresh(self):
        self._refresh_view_settings()
        #self.refresh_memory()
        self.viewport().update()

    def _refresh_display(self):
        print("TODO: Recompute / redraw the hex display (but do not fetch new data)")
        self.viewport().update()

    def _refresh_view_settings(self):

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
        self.setMinimumWidth(self._pos_aux + self._width_aux)

    def full_size(self):
        if not self.model.data:
            return QtCore.QSize(0, 0)

        width = self._pos_aux + (self.model.num_bytes_per_line * self._char_width)
        height = len(self.model.data) // self.model.num_bytes_per_line
        if len(self.model.data) % self.model.num_bytes_per_line:
            height += 1

        height *= self._char_height

        return QtCore.QSize(width, height)

    def resizeEvent(self, event):
        super(HexView, self).resizeEvent(event)
        self._refresh_view_settings()
        self.controller.set_data_size(self.num_bytes_visible)
        #self.model.last_address = self.model.address + self.num_bytes_visible
        #if self._reader:
        #    self.refresh_memory()

    def keyPressEvent(self, e):
        if e.key() == QtCore.Qt.Key_G:
            import ida_kernwin, ida_idaapi
            address = ida_kernwin.ask_addr(self.model.address, "Jump to address in memory")
            if address != ida_idaapi.BADADDR:
                self.controller.navigate(address)
                e.accept()
        return super(HexView, self).keyPressEvent(e)

    #-------------------------------------------------------------------------
    # Painting
    #-------------------------------------------------------------------------

    def paintEvent(self, event):
        #super(HexView, self).paintEvent(event)

        if not self.model.data:
            return

        painter = QtGui.QPainter(self.viewport())

        area_size = self.viewport().size()
        widget_size = self.full_size()

        # paint background of entire scroll area
        painter.fillRect(event.rect(), self._palette.hex_data_bg)

        # paint address area background
        address_area_rect = QtCore.QRect(0, event.rect().top(), self._width_addr, self.height())
        painter.fillRect(address_area_rect, self._palette.hex_address_bg)

        # paint line between address area and hex area
        painter.setPen(self._palette.hex_separator)
        painter.drawLine(self._width_addr, event.rect().top(), self._width_addr, self.height())

        # paint line between hex area and auxillary area
        line_pos = self._pos_aux
        painter.setPen(self._palette.hex_separator)
        painter.drawLine(line_pos, event.rect().top(), line_pos, self.height())

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
        painter.drawText(self._pos_addr, y, address_text)
        
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

                painter.drawText(x_pos_aux, y, ch)
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

        byte_address = self.model.address + byte_idx

        #
        # paint text selection background color / highlight
        #

        x_bg = x - (self._char_width // 2) * padding
        y_bg = y - self._char_descent

        width = self._char_width * (len(text) + padding)
        height = self._char_height

        bg_color = None
        border_color = None

        # a byte that was written
        if byte_address in self.model.delta.mem_writes:
            bg_color = self._palette.mem_write_bg
            fg_color = self._palette.mem_write_fg

        # a byte that was read
        elif byte_address in self.model.delta.mem_reads:
            bg_color = self._palette.mem_read_bg
            fg_color = self._palette.mem_read_fg

        # a selected byte
        if self._select_begin <= byte_address < self._select_end:

            # the selection is a focused, navigation breakpoint
            if self.selection_size == 1 or self._region_access:

                if not bg_color:
                    bg_color = self._palette.navigation_selection_bg
                    if self.model.mask[byte_idx]:
                        fg_color = self._palette.navigation_selection_fg
                    else:
                        fg_color = self._palette.navigation_selection_faded_fg

                border_color = self._palette.navigation_selection_bg

            # nothing fancy going on, just standard text selection
            else:
                bg_color = self._palette.standard_selection_bg

                # set the text color for selected text
                if self.model.mask[byte_idx]:
                    fg_color = self._palette.standard_selection_fg

        # the byte is highlighted in some fashion, paint it now
        if bg_color:

            if border_color and not self._region_access:
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
            painter.drawRect(x_bg, y_bg, width, height)

        painter.setPen(fg_color)

        #
        # paint text
        #

        painter.drawText(x, y, text)

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

        # draw the pointer!!
        #print("Drawing pointer!!")
        pointer_str = ("0x%08X " % value).rjust(num_chars)
        painter.drawText(x, y, pointer_str)
        x += num_chars * self._char_width

        return (byte_idx + self.model.pointer_size, x, y)

    #-------------------------------------------------------------------------
    #
    #-------------------------------------------------------------------------

    def mousePressEvent(self, event):
        byte_address = self.point_to_address(event.pos())
        #print("Clicked 0x%08X (press event)" % byte_address)

        if event.button() == QtCore.Qt.LeftButton:
            if byte_address != -1:
                self.reset_selection(byte_address)
            else:
                self.reset_selection()

        elif event.button() == QtCore.Qt.RightButton:
            if self.selection_size <= 1 and byte_address != -1:
                self.reset_selection(byte_address)

        self.viewport().update()

    def mouseMoveEvent(self, event):
        byte_address = self.point_to_address(event.pos())
        #print("Move 0x%08X" % byte_address)

        self.set_selection(byte_address)
        self.viewport().update()

    def mouseReleaseEvent(self, event):
        byte_address = self.point_to_address(event.pos())
        #print("Release 0x%08X" % byte_address)

        if self.selection_size == 1:
            self.controller.focus_address_access(byte_address)

        self.viewport().update()

    def point_to_index(self, position):
        """
        Convert a QPoint (x, y) on the hex view window to a byte index.
        """
        padding = self._char_width // 2

        if position.x() < (self._pos_hex - padding):
            return -1

        if position.x() >= (self._pos_hex + self._width_hex - padding):
            return -1

        # convert 'gloabl' x in the viewport, to an x that is 'relative' to the hex area
        hex_x = (position.x() - self._pos_hex) - (self._char_width // 2)
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
        #print("- Item X", item_index)

        # compute which byte is hovered in the item
        item_byte_x = int(hex_x % item_width_padded)
        item_byte_index = int(item_byte_x // (self._char_width * 2))
        #print("- Item Byte X", item_byte_x)
        #print("- Item Byte Index", item_byte_index)

        if self.model.hex_format != HexType.BYTE:
            item_byte_index = HEX_TYPE_WIDTH[self.model.hex_format] - item_byte_index - 1

        byte_x = item_index * HEX_TYPE_WIDTH[self.model.hex_format] + item_byte_index

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
            return -1

        byte_address = self.model.address + byte_index
        return byte_address 

    def reset_selection(self, address=-1):
        self._region_access = False

        if address == -1:
            self._select_init = address
            self._select_begin = address
            self._select_end = address
        else:
            self._select_init = address
            self._select_begin = address
            self._select_end = address + 1

    def set_selection(self, address):
        
        if address >= self._select_init:
            self._select_end = address + 1
            self._select_begin = self._select_init
        else:
            self._select_begin = address
            self._select_end = self._select_init + 1

    def wheelEvent(self, event):

        #
        # first, we will attempt special handling of the case where a user
        # 'scrolls' up or down when hovering their cursor over a byte they
        # have selected...
        #

        # compute the address of the hovered byte (if there is one...)
        address = self.point_to_address(event.pos())
        if address != -1:

            #print(f"SCROLLING {self._select_begin:08X} <= {address:08X} <= {self._select_end:08X}")

            # is the hovered byte one that is selected?
            if (self._select_begin <= address <= self._select_end):
                access_type = BreakpointType.ACCESS
                length = self.selection_size

                #
                # if a region is selected with an 'access' breakpoint on it,
                # use the start address of the selected region instead for
                # the region-based seeks
                #

                if self.selection_size > 1 and self._region_access:
                    address = self._select_begin

                # scrolled 'up'
                if event.angleDelta().y() > 0:
                    self.controller.reader.seek_to_prev(address, access_type, length)

                # scrolled 'down'
                elif event.angleDelta().y() < 0:
                    self.controller.reader.seek_to_next(address, access_type, length)

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
