from tenet.hex import HexController

#------------------------------------------------------------------------------
# memory.py -- Memory Dump Controller
#------------------------------------------------------------------------------
#
#    The purpose of this file is to house the 'headless' components of the
#    memory dump window and its underlying functionality. This is split into
#    a model and controller component, of a typical 'MVC' design pattern. 
#
#    As our memory dumps are largely abstracted off a generic 'hex dump',
#    there is very little code that actually has to be applied here (for now)
#

class MemoryController(HexController):
    """
    The Memory Dump Controller (Logic)
    """

    def __init__(self, pctx):
        super(MemoryController, self).__init__(pctx)
        self._title = "Memory View"
        #self.model.hex_format = HexType.MAGIC
