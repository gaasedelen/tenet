import re
import json
import logging
import threading

from urllib.request import urlopen

logger = logging.getLogger("Tenet.Util.Update")

#------------------------------------------------------------------------------
# Update Checking
#------------------------------------------------------------------------------

UPDATE_URL = "https://api.github.com/repos/gaasedelen/tenet/releases/latest"

def check_for_update(current_version, callback):
    """
    Perform a plugin update check.
    """
    update_thread = threading.Thread(
        target=async_update_check,
        args=(current_version, callback,),
        name="UpdateChecker"
    )
    update_thread.start()

def async_update_check(current_version, callback):
    """
    An async worker thread to check for an plugin update.
    """
    logger.debug("Checking for update...")

    try:
        response = urlopen(UPDATE_URL, timeout=5.0)
        html = response.read()
        info = json.loads(html)
        remote_version = info["tag_name"]
    except Exception:
        logger.debug(" - Failed to reach GitHub for update check...")
        return

    # convert vesrion #'s to integer for easy compare...
    version_remote = int(''.join(re.findall(r'\d+', remote_version)))
    version_local = int(''.join(re.findall(r'\d+', current_version)))

    # no updates available...
    logger.debug(" - Local: 'v%s' vs Remote: '%s'" % (current_version, remote_version))
    if version_local >= version_remote:
        logger.debug(" - No update needed...")
        return

    # notify the user if an update is available
    update_message = "An update is available for Tenet!\n\n" \
                     " -  Latest Version: %s\n" % (remote_version) + \
                    " - Current Version: v%s\n\n" % (current_version) + \
                    "Please go download the update from GitHub."

    callback(update_message)

