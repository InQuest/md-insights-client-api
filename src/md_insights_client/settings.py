"Settings handler for MD InSights client"

import logging
from pathlib import Path
from types import SimpleNamespace

from yaml import safe_load


# Use the Eyelet API service
MD_INSIGHTS_API_HOST = "https://eyelet.inquest.net"

# Miscellaneous settings
DEFAULT_LOGLEVEL = "info"
CHOICE_LOG_LEVELS = ["critical", "error", "warning", "info", "debug"]

CONFIG_FILE_DEFAULT = "~/.md-insights.yml"


logging.basicConfig(
    level=DEFAULT_LOGLEVEL.upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
)


class SettingsLoader:
    """Load client settings.

    Settings are loaded from the configuration file. A default configuration
    file path is used by default, and this may be overridden by a custom file
    path.
    """

    def __init__(self, conf_file: str = CONFIG_FILE_DEFAULT):
        """Initialize settings loader.

        Arguments:

        - conf_file: Configuration file path. The path may be specified as a
          relative paths as well as a user path (using a tilde (`~`) to
          represent the home directory, in which case it will be resolved to
          the file system path).
        """

        self.conf_file = Path(conf_file).expanduser().absolute()

        with self.conf_file.open("r") as c:
            self.config_dict = safe_load(c)
        self.config_dict["conf_file"] = str(self.conf_file)
        self.config = SimpleNamespace(**self.config_dict)

        # Set an explicit default logging level if absent in the
        # configuration
        if not getattr(self.config, "log_level", None):
            self.config.log_level = DEFAULT_LOGLEVEL

    def get_config(self):
        return self.config
