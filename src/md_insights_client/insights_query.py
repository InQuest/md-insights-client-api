"""
Query client for MetaDefender InSights threat intelligence APIs. This client
provides C2 and reputation queries for IP addresses and domain names.
"""

import json
import logging
import re
from argparse import ArgumentParser
from importlib.metadata import version
from ipaddress import ip_address
from tabulate import tabulate
from typing import List, Union

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


def _listify(obj):
    """Convert input to a list if it's not already one."""
    if obj is None:
        return []
    if isinstance(obj, list):
        return obj
    else:
        return [obj]


def _chunks(lst, n):
    """Yield successive n-sized chunks from list."""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def _is_ip_address(artifact: str) -> bool:
    """Check if artifact is an IP address."""
    try:
        ip_address(artifact)
        return True
    except ValueError:
        return False


def _is_domain_name(artifact: str) -> bool:
    """Check if artifact is a domain name."""
    if _is_ip_address(artifact):
        return False

    # Basic domain validation - contains at least one dot and valid characters
    domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    return bool(re.match(domain_pattern, artifact)) and "." in artifact


def _merge_results(
    reputation_data: dict, c2_data: dict, artifacts: List[str]
) -> dict:
    """Merge reputation and C2 query results into a single structure."""
    merged = {
        "results": {},
        "summary": {
            "total_artifacts": len(artifacts),
            "reputation_queries": len(reputation_data.get("records", {})),
            "c2_queries": len(c2_data.get("details", {})),
        },
    }

    # Process each artifact
    for artifact in artifacts:
        artifact_result = {
            "artifact_type": "ip" if _is_ip_address(artifact) else "domain",
            "reputation": None,
            "c2": None,
        }

        # Add reputation data if available
        if artifact in reputation_data.get("records", {}):
            artifact_result["reputation"] = reputation_data["records"][
                artifact
            ]

        # Add C2 data if available
        if artifact in c2_data.get("details", {}):
            artifact_result["c2"] = c2_data["details"][artifact]

        merged["results"][artifact] = artifact_result

    return merged


def c2_dns_query(api_key: str, artifacts: Union[str, List[str]]) -> dict:
    """Query the InSights API to determine if domain names are C2 endpoints.

    Arguments:
    - api_key: MD InSights API key provisioned by OPSWAT.
    - artifacts: A domain name or list of domain names to query.

    Returns:
    - Dictionary containing query results.
    """
    if not api_key:
        raise ConfigurationError(
            "MD InSights API key is missing and must be provided"
        )

    data = {
        "api_key": api_key,
        "artifacts": json.dumps(_listify(artifacts)),
    }

    logging.debug(
        "requesting C2 DNS query for %d artifacts through host %s",
        len(_listify(artifacts)),
        MD_INSIGHTS_API_HOST,
    )

    try:
        response = requests.post(
            f"{MD_INSIGHTS_API_HOST}/c2/dns/query", data=data
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        if hasattr(response, "text") and response.text:
            logging.error(
                "response body from server response: %s", response.text
            )
        raise FeedAccessError(f"API error attempting C2 DNS query: {e}")


def c2_ip_query(api_key: str, artifacts: Union[str, List[str]]) -> dict:
    """Query the InSights API to determine if IP addresses are C2 endpoints.

    Arguments:
    - api_key: MD InSights API key provisioned by OPSWAT.
    - artifacts: An IP address or list of IP addresses to query.

    Returns:
    - Dictionary containing query results.
    """
    if not api_key:
        raise ConfigurationError(
            "MD InSights API key is missing and must be provided"
        )

    data = {
        "api_key": api_key,
        "artifacts": json.dumps(_listify(artifacts)),
    }

    logging.debug(
        "requesting C2 IP query for %d artifacts through host %s",
        len(_listify(artifacts)),
        MD_INSIGHTS_API_HOST,
    )

    try:
        response = requests.post(
            f"{MD_INSIGHTS_API_HOST}/c2/ip/query", data=data
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        if hasattr(response, "text") and response.text:
            logging.error(
                "response body from server response: %s", response.text
            )
        raise FeedAccessError(f"API error attempting C2 IP query: {e}")


def reputation_query(
    api_key: str, artifacts: Union[str, List[str]], max_at_a_time: int = 100
) -> dict:
    """Query the InSights API to determine reputation of IP/domain artifacts.

    Arguments:
    - api_key: MD InSights API key provisioned by OPSWAT.
    - artifacts: An IP address/domain or list of IP addresses/domains to query.
    - max_at_a_time: Maximum number of artifacts to query per API call.

    Returns:
    - Dictionary containing query results with 'records' key.
    """
    if not api_key:
        raise ConfigurationError(
            "MD InSights API key is missing and must be provided"
        )

    artifacts_list = _listify(artifacts)
    records = {}

    for chunk in _chunks(artifacts_list, max_at_a_time):
        data = {
            "api_key": api_key,
            "artifacts": json.dumps(chunk),
        }

        logging.debug(
            "requesting reputation query for %d artifacts through host %s",
            len(chunk),
            MD_INSIGHTS_API_HOST,
        )

        try:
            response = requests.post(
                f"{MD_INSIGHTS_API_HOST}/rep/query", data=data
            )
            response.raise_for_status()
            response_data = response.json()

            for k, v in response_data.get("records", {}).items():
                if k not in records:
                    records[k] = v

        except Exception as e:
            if hasattr(response, "text") and response.text:
                logging.error(
                    "response body from server response: %s", response.text
                )
            raise FeedAccessError(
                f"API error attempting reputation query: {e}"
            )

    return {"records": records}


def all_query(
    api_key: str, artifacts: Union[str, List[str]], max_at_a_time: int = 100
) -> dict:
    """Query all available APIs (reputation + C2) for the given artifacts.

    Automatically detects artifact types and runs appropriate queries:
    - All artifacts: reputation query
    - IP addresses: C2 IP query
    - Domain names: C2 DNS query

    Arguments:
    - api_key: MD InSights API key provisioned by OPSWAT.
    - artifacts: IP address(es) and/or domain name(s) to query.
    - max_at_a_time: Maximum number of artifacts to query per API call.

    Returns:
    - Dictionary containing merged results from all applicable queries.
    """
    if not api_key:
        raise ConfigurationError(
            "MD InSights API key is missing and must be provided"
        )

    artifacts_list = _listify(artifacts)

    # Separate artifacts by type
    ip_artifacts = [a for a in artifacts_list if _is_ip_address(a)]
    domain_artifacts = [a for a in artifacts_list if _is_domain_name(a)]

    logging.debug(
        "all query: %d total artifacts (%d IPs, %d domains)",
        len(artifacts_list),
        len(ip_artifacts),
        len(domain_artifacts),
    )

    # Always query reputation for all artifacts
    reputation_data = reputation_query(api_key, artifacts_list, max_at_a_time)

    # Query C2 endpoints based on artifact types
    c2_data = {"details": {}}

    if ip_artifacts:
        try:
            c2_ip_result = c2_ip_query(api_key, ip_artifacts)
            c2_data["details"].update(c2_ip_result.get("details", {}))
        except Exception as e:
            logging.warning("C2 IP query failed: %s", e)

    if domain_artifacts:
        try:
            c2_dns_result = c2_dns_query(api_key, domain_artifacts)
            c2_data["details"].update(c2_dns_result.get("details", {}))
        except Exception as e:
            logging.warning("C2 DNS query failed: %s", e)

    # Merge all results
    return _merge_results(reputation_data, c2_data, artifacts_list)


def cli():
    """Command line interface"""

    description = "Query MetaDefender InSights threat intelligence APIs"
    parser = ArgumentParser(description=description)
    parser.add_argument(
        "-c",
        "--config-file",
        default=CONFIG_FILE_DEFAULT,
        help="configuration file path (default: %(default)s)",
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="output raw JSON data from API response",
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

    # Query type subcommands
    subparsers = parser.add_subparsers(dest="query_type", help="Query type")

    # C2 DNS subcommand
    c2_dns_parser = subparsers.add_parser(
        "c2-dns", help="Query C2 DNS endpoints"
    )
    c2_dns_parser.add_argument(
        "artifacts",
        nargs="+",
        help="Domain names to query",
    )

    # C2 IP subcommand
    c2_ip_parser = subparsers.add_parser("c2-ip", help="Query C2 IP endpoints")
    c2_ip_parser.add_argument(
        "artifacts",
        nargs="+",
        help="IP addresses to query",
    )

    # Reputation subcommand
    rep_parser = subparsers.add_parser("reputation", help="Query reputation")
    rep_parser.add_argument(
        "artifacts",
        nargs="+",
        help="IP addresses or domains to query",
    )
    rep_parser.add_argument(
        "--max-batch-size",
        type=int,
        default=100,
        help="Maximum artifacts per API call (default: %(default)s)",
    )

    # All queries subcommand
    all_parser = subparsers.add_parser(
        "all",
        help="Query reputation and C2 data (auto-detects artifact types)",
    )
    all_parser.add_argument(
        "artifacts",
        nargs="+",
        help="IP addresses and/or domain names to query",
    )
    all_parser.add_argument(
        "--max-batch-size",
        type=int,
        default=100,
        help="Maximum artifacts per API call (default: %(default)s)",
    )

    args = parser.parse_args()

    if not args.query_type:
        parser.error("A query type must be specified")

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
        if args.query_type == "c2-dns":
            result = c2_dns_query(settings.api_key, args.artifacts)
            headers = ["artifact", "details"]
            data = []
            if result["details"]:
                data.append(headers)
                for artifact, details in result["details"].items():
                    data.append([artifact, details])
        elif args.query_type == "c2-ip":
            result = c2_ip_query(settings.api_key, args.artifacts)
            headers = ["artifact"]
            data = []
            if result["details"]:
                for artifact, details in result["details"].items():
                    rowdata = [artifact]
                    dfields = details.keys()
                    if "asn" in dfields:
                        if details.get("asn"):
                            headers.append("asn")
                            rowdata.append(details["asn"])
                    if "country" in dfields:
                        if details.get("country"):
                            headers.append("country")
                            rowdata.append(details["country"])
                    headers.append("description")
                    rowdata.append(details["description"])
                    data.append(rowdata)
                data.insert(0, headers)
        elif args.query_type == "reputation":
            result = reputation_query(
                settings.api_key, args.artifacts, args.max_batch_size
            )
            headers = [
                "artifact",  # artifact name
                "score",  # score (int)
                "src_count",  # alarmed/evaluated
                "inquest",  # bool
                "opswat",  # bool
                "rep_srcs",  # list of sources (combined)
            ]
            data = []
            for artifact, details in result["records"].items():
                if details["sources_alarmed"] != 0:
                    srcs = []
                    rowdata = [artifact]
                    rowdata.append(details["score"])
                    src_count = (
                        f'{details["sources_alarmed"]}'
                        f'/{details["sources_evaluated"]}'
                    )
                    rowdata.append(src_count)
                    for ds in ("inquest", "opswat"):
                        if details["report"][ds].get("hits"):
                            rowdata.append("Y")
                            srcs.extend(details["report"][ds]["sources"])
                        else:
                            rowdata.append("N")
                    rowdata.append(", ".join(srcs))
                    data.append(rowdata)
            if data:
                data.insert(0, headers)
        elif args.query_type == "all":
            result = all_query(
                settings.api_key, args.artifacts, args.max_batch_size
            )
            headers = [
                "artifact",  # artifact name
                "score",  # score (int)
                "rep",  # reputation hit (bool)
                "c2",  # c2 hit (bool)
                "src_count",  # alarmed/evaluated
                "inquest",  # bool
                "opswat",  # bool
                "rep_srcs",  # list of sources (combined)
                "c2_desc",  # C2 description
            ]
            data = []
            for artifact, details in result["results"].items():
                if details["c2"] or details["reputation"]["score"] != 0:
                    srcs = []
                    rowdata = [artifact]
                    rep_score = details["reputation"]["score"]
                    if isinstance(details["c2"], str):
                        c2_details = details["c2"]
                    elif isinstance(details["c2"], dict):
                        c2_details = details["c2"].get("description")
                    else:
                        logging.warning(
                            "artifact C2 field contains unexpected data: %s",
                            details.get("c2"),
                        )
                        c2_details = None
                    rowdata.append(rep_score)
                    src_count = (
                        f'{details["reputation"]["sources_alarmed"]}'
                        f'/{details["reputation"]["sources_evaluated"]}'
                    )
                    rep_hit = "Y" if rep_score else "N"
                    c2_hit = "Y" if c2_details else "N"
                    rowdata.append(rep_hit)
                    rowdata.append(c2_hit)
                    rowdata.append(src_count)
                    for ds in ("inquest", "opswat"):
                        if details["reputation"]["report"][ds].get("hits"):
                            rowdata.append("Y")
                            srcs.extend(
                                details["reputation"]["report"][ds]["sources"]
                            )
                        else:
                            rowdata.append("N")
                    rowdata.append(", ".join(srcs))
                    rowdata.append(c2_details)
                    data.append(rowdata)
            if data:
                data.insert(0, headers)

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if data:
                print(tabulate(data, headers="firstrow"))
    except (ConfigurationError, FeedAccessError, ValueError) as e:
        parser.error(f"Error attempting to query API: {e}")
