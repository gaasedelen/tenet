import logging

from tenet.util.log import lmsg
from tenet.integration.binja_integration import TenetBinja

logger = logging.getLogger("Tenet.Binja.Loader")

#------------------------------------------------------------------------------
# TenetBinja Loader
#------------------------------------------------------------------------------
#
#    The Binary Ninja plugin loading process is less involved compared to IDA.
#
#    When Binary Ninja is starting up, it will import all python files placed
#    in its root plugin folder. It will then attempt to import any *directory*
#    in the plugin folder as a python module.
#
#    For this reason, you may see Binary Ninja attempting to load 'tenet'
#    and 'tenet_plugin' in your console. This is normal due to the way
#    we have structured tenet and its loading process.
#
#    In practice, tenet_plugin.py will import the contents of this file,
#    when Binary Ninja is starting up. As such, this is our only opportunity
#    to load & integrate tenet.
#

try:
    tenet = TenetBinja()
    tenet.load()
except Exception as e:
    lmsg("Failed to initialize tenet")
    logger.exception("Exception details:")