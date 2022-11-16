#--------------------------------------------------------------------------
# Disassembler API Selector
#--------------------------------------------------------------------------
#
#    this file will select and load the shimmed disassembler API for the
#    appropriate (current) disassembler platform.
#
#    see api.py for more details regarding this API shim layer
#

disassembler = None

#--------------------------------------------------------------------------
# IDA API Shim
#--------------------------------------------------------------------------

if disassembler == None:
    try:
        print("IDA")
        from .ida_api import IDACoreAPI, IDAContextAPI, DockableWindow 
        disassembler = IDACoreAPI()
        DisassemblerContextAPI = IDAContextAPI
    except ImportError as e:
        print(e)

#--------------------------------------------------------------------------
# Binary Ninja API Shim
#--------------------------------------------------------------------------

if disassembler == None:
    try:
        print("Binja")
        from .binja_api import BinjaCoreAPI, BinjaContextAPI, DockableWindow
        disassembler = BinjaCoreAPI()
        DisassemblerContextAPI = BinjaContextAPI
    except ImportError as e:
        print(e)

#--------------------------------------------------------------------------
# Unknown Disassembler
#--------------------------------------------------------------------------

if disassembler == None:
    raise NotImplementedError("Unknown or unsupported disassembler!")

