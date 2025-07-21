from tenet.util.log import logging_started, start_logging
from tenet.integration.api import disassembler

if not logging_started():
    logger = start_logging()

#------------------------------------------------------------------------------
# Disassembler Agnonstic Plugin Loader
#------------------------------------------------------------------------------

logger.debug("Resolving disassembler platform for Tenet...")

if disassembler.headless:
    logger.info("Disassembler '%s' is running headlessly" % disassembler.NAME)
    logger.info(" - Tenet is not supported in headless modes (yet!)")

elif disassembler.NAME == "IDA":
    logger.info("Selecting IDA loader...")
    from tenet.integration.ida_loader import *

else:
    raise NotImplementedError("DISASSEMBLER-SPECIFIC SHIM MISSING")

