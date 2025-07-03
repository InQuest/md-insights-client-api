"""
This client fetches MetaDefender InSights feed snapshots. This requires an API
key provisioned for access.
"""

import gzip
import logging
import re
import shutil
from argparse import ArgumentParser
from datetime import datetime
from importlib.metadata import version

import requests

from .exceptions import ConfigurationError, FeedAccessError
from .settings import (
    CHOICE_LOG_LEVELS,
    CONFIG_FILE_DEFAULT,
    DEFAULT_LOGLEVEL,
    MD_INSIGHTS_API_HOST,
    SettingsLoader,
)

__application_name__ = "md-insights-client"
__version__ = version(__application_name__)


def fetch_feeds(api_key, feeds=[]):
    """Fetch MD InSights feeds.

    Retrieve one or more MetaDefender InSights threat intelligence feed
    snapshots. The client downloads compressed feed JSON files from the API.
    Feed files are downloaded, uncompressed, and stored in datestamped output
    files.

    Arguments:

    - api_key: MD InSights API key provisioned by OPSWAT.
    - feeds: A list of one or more InSights snapshot feed names to download.
    """

    if not api_key:
        raise ConfigurationError(
            "MD InSights API key is missing and must be provided"
        )

    if not feeds:
        raise ValueError(
            "At least one feed name must be enabled in the configuration"
        )

    for feed in feeds:
        logging.debug(
            "requesting snapshot of %s for key %s through host %s",
            feed,
            api_key[:8],
            MD_INSIGHTS_API_HOST,
        )

        # Call to the API
        response = requests.post(
            f"{MD_INSIGHTS_API_HOST}/api/insights/{feed}",
            data={"api_key": api_key},
        )
        try:
            response.raise_for_status()
        except Exception as e:
            if response.text:
                logging.error(
                    "response body from server response: %s", response.text
                )
            raise FeedAccessError(
                f"API error attempting to retrieve feed: {e}"
            )

        # Check if the response is a JSON error instead of gzipped content
        content_type = response.headers.get("Content-Type", "")
        if "application/json" in content_type or response.content.startswith(
            b"{"
        ):
            try:
                import json

                error_data = json.loads(response.content.decode("utf-8"))
                if "error" in error_data:
                    raise FeedAccessError(
                        f"API error for feed '{feed}': {error_data['error']}"
                    )
                else:
                    raise FeedAccessError(
                        f"Unexpected JSON response for feed '{feed}': {error_data}"
                    )
            except json.JSONDecodeError:
                raise FeedAccessError(
                    f"Invalid response format for feed '{feed}': {response.content.decode('utf-8', errors='replace')}"
                )

        # Extract filename from response header
        content_disposition = response.headers.get("Content-Disposition")
        if content_disposition:
            gz_file = (
                re.findall("filename=(.+)", content_disposition)[0]
                .strip('"')
                .strip("'")
            )
        else:
            gz_file = f"{feed}.json.gz"

        # Write response data to disk
        with open(gz_file, "wb+") as fh:
            fh.write(response.content)
        logging.info("wrote %d bytes to %s", len(response.content), gz_file)

        # Decompress and write response data out to a datestamped file
        try:
            with gzip.open(gz_file, "rb") as f_in:
                # Example: inquest-insights-c2-ip.json.gz
                #       -> inquest-insights-c2-ip-20241029.json
                today_str = datetime.today().strftime("%Y%m%d")
                out_filename = re.sub(
                    r"\.json\.gz$", f"-{today_str}.json", gz_file
                )
                with open(out_filename, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
                logging.info(
                    "wrote uncompressed feed data to %s\n", out_filename
                )
        except gzip.BadGzipFile:
            # If we get here, the file isn't gzipped - check if it's an error response
            try:
                import json

                with open(gz_file, "r") as f:
                    error_data = json.load(f)
                if "error" in error_data:
                    raise FeedAccessError(
                        f"API error for feed '{feed}': {error_data['error']}"
                    )
                else:
                    raise FeedAccessError(
                        f"Unexpected response format for feed '{feed}': {error_data}"
                    )
            except json.JSONDecodeError:
                raise FeedAccessError(
                    f"Response is not a valid gzipped file or JSON error for feed '{feed}'"
                )
        except Exception as e:
            raise FeedAccessError(f"Error processing feed '{feed}': {e}")


def cli():
    "Command line interface"

    description = "Fetch MetaDefender InSights feed snapshots"
    parser = ArgumentParser(description=description)
    parser.add_argument(
        "-c",
        "--config-file",
        default=CONFIG_FILE_DEFAULT,
        help="configuration file path (default: %(default)s)",
    )
    parser.add_argument(
        "-l",
        "--log-level",
        choices=CHOICE_LOG_LEVELS,
        help=f"set logging to specified level (default: {DEFAULT_LOGLEVEL})",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=__version__,
        help="print package version",
    )

    args = parser.parse_args()

    try:
        sl = SettingsLoader(args.config_file)
        settings = sl.get_config()
    except FileNotFoundError as e:
        parser.error(f"unable to load specified configuration: {e}")

    log_level = args.log_level or settings.log_level
    try:
        logging.getLogger().setLevel(log_level.upper())
    except ValueError as e:
        parser.error(f"unable to set specified logging level: {e}")

    if log_level == "debug":
        from copy import deepcopy
        from re import sub

        sanitized_settings = deepcopy(settings)
        sanitized_settings.api_key = sub(
            r"^(.{8}).*$", r"\1...", settings.api_key
        )
        logging.debug("invocation args: type=%s, %s", type(args), args)
        logging.debug("invocation settings: %s", sanitized_settings)
        logging.debug(
            "log level: %s", logging.getLevelName(logging.getLogger().level)
        )

    try:
        fetch_feeds(
            api_key=settings.api_key,
            feeds=settings.md_insights_feeds,
        )
    except (ConfigurationError, FeedAccessError, ValueError) as e:
        parser.error(f"Error attempting to retrieve feed: {e}")
