import enum

#-----------------------------------------------------------------------------
# types.py -- Plugin Types
#-----------------------------------------------------------------------------
#
#    This purpose of this file is to host basic types / primitievs that
#    may need to be used cross-plugin, and could be prone to causing 
#    cyclic dependency problems if left with their respective subsystems.
#

#-----------------------------------------------------------------------------
# Hexdump Types
#-----------------------------------------------------------------------------

class HexType(enum.Enum):
    BYTE    = 0
    SHORT   = 1
    DWORD   = 2
    QWORD   = 3
    POINTER = 4
    MAGIC   = 5

class AuxType(enum.Enum):
    NONE  = 0
    ASCII = 1
    STACK = 2

HEX_TYPE_WIDTH = \
{
    HexType.BYTE:    1,
    HexType.SHORT:   2,
    HexType.DWORD:   4,
    HexType.QWORD:   8,
    HexType.POINTER: 8,  # XXX: should be 4 or 8
    HexType.MAGIC:   1,
}

class HexItem(object):
    def __init__(self, value, mask, width, item_type):
        self.value = value
        self.mask = mask
        self.width = width # width in bytes
        self.type = item_type

#-----------------------------------------------------------------------------
# Breakpoint Types
#-----------------------------------------------------------------------------

class BreakpointType(enum.IntEnum):
    NONE   = 1 << 0
    READ   = 1 << 1
    WRITE  = 1 << 2
    EXEC   = 1 << 3
    ACCESS = (READ | WRITE)

class BreakpointEvent(enum.Enum):
    ADDED    = 0
    REMOVED  = 1
    ENABLED  = 2
    DISABLED = 3

class TraceBreakpoint(object):
    """
    A simple class to encapsulate the properties of a breakpoint definition.
    """
    def __init__(self, address, access_type=BreakpointType.NONE, length=1):
        assert not(address is None)
        self.type = access_type
        self.address = address
        self.length = length
        self.enabled = True