#!/usr/bin/env python3
"""
CLI for Anomali ThreatStream enrichment using MD Insights data.
"""

import json
import logging
from argparse import ArgumentParser
from importlib.metadata import version

from .exceptions import ConfigurationError
from .settings import (
    CHOICE_LOG_LEVELS,
    CONFIG_FILE_DEFAULT,
    DEFAULT_LOGLEVEL,
    SettingsLoader,
)
from .anomali_threatstream import ThreatStreamClient, process_insights_enrichment
from .insights_query import all_query

__application_name__ = "md-insights-client"
__version__ = version(__application_name__)


def cli():
    """Command line interface for ThreatStream enrichment."""
    
    description = (
        "Push MD Insights enrichment data to Anomali ThreatStream. "
        "This tool queries MD Insights for threat intelligence about IOCs "
        "and automatically pushes the enrichment data to ThreatStream."
    )
    
    parser = ArgumentParser(description=description)
    parser.add_argument(
        "artifacts",
        nargs="+",
        help="IP addresses and/or domain names to enrich in ThreatStream",
    )
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
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="query MD Insights but don't push to ThreatStream (preview mode)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="output JSON format of enrichment results",
    )
    parser.add_argument(
        "--api-key",
        help="override Anomali API key from config (format: username:apikey)",
    )
    parser.add_argument(
        "--api-url",
        help="override Anomali API URL from config",
    )
    parser.add_argument(
        "--source-name",
        help="override source name for ThreatStream (default: OPSWAT_MDInSights)",
    )
    parser.add_argument(
        "--tlp",
        choices=["white", "green", "amber", "red"],
        help="override Traffic Light Protocol setting",
    )
    
    args = parser.parse_args()
    
    # Load configuration
    try:
        sl = SettingsLoader(args.config_file)
        settings = sl.get_config()
    except FileNotFoundError as e:
        parser.error(f"unable to load specified configuration: {e}")
    
    # Set logging level
    log_level = args.log_level or settings.log_level
    try:
        logging.getLogger().setLevel(log_level.upper())
    except ValueError as e:
        parser.error(f"unable to set specified logging level: {e}")
    
    # Check MD Insights API key
    if not getattr(settings, 'api_key', None):
        parser.error(
            "MD Insights API key is required. "
            "Please set 'api_key' in your configuration file."
        )
    
    # Get Anomali configuration (from args or settings)
    anomali_api_key = args.api_key or getattr(settings, 'anomali_api_key', None)
    anomali_api_url = args.api_url or getattr(settings, 'anomali_api_url', None)
    anomali_source = args.source_name or getattr(settings, 'anomali_source_name', None)
    anomali_tlp = args.tlp or getattr(settings, 'anomali_tlp', None)
    
    if not args.dry_run and not anomali_api_key:
        parser.error(
            "Anomali API key is required (unless using --dry-run). "
            "Set 'anomali_api_key' in config or use --api-key argument."
        )
    
    try:
        # Query MD Insights for all artifacts
        logging.info(f"Querying MD Insights for {len(args.artifacts)} artifacts...")
        insights_result = all_query(settings.api_key, args.artifacts)
        
        # Filter out artifacts with no enrichment data
        enriched_artifacts = {}
        for artifact, details in insights_result.get('results', {}).items():
            has_reputation = (
                details.get('reputation') and 
                details['reputation'].get('score', 0) > 0
            )
            has_c2 = details.get('c2') and details['c2'] != 'null'
            
            if has_reputation or has_c2:
                enriched_artifacts[artifact] = details
        
        if not enriched_artifacts:
            print("No enrichment data found for the specified artifacts.")
            return
        
        print(f"\nFound enrichment data for {len(enriched_artifacts)} artifacts:")
        for artifact, details in enriched_artifacts.items():
            rep_score = details.get('reputation', {}).get('score', 0) if details.get('reputation') else 0
            c2_info = details.get('c2', 'None')
            print(f"  - {artifact}: reputation={rep_score}, c2={c2_info}")
        
        if args.dry_run:
            print("\n[DRY RUN] Would push the above enrichments to ThreatStream")
            if args.json:
                print("\nEnrichment data:")
                print(json.dumps({'results': enriched_artifacts}, indent=2))
            return
        
        # Push to ThreatStream
        print("\nPushing enrichments to ThreatStream...")
        ts_client = ThreatStreamClient(
            api_key=anomali_api_key,
            base_url=anomali_api_url,
            source_name=anomali_source,
            tlp=anomali_tlp
        )
        
        enrichment_result = process_insights_enrichment(
            {'results': enriched_artifacts},
            ts_client
        )
        
        # Report results
        print("\nThreatStream enrichment complete:")
        print(f"  - Processed: {enrichment_result['processed']} artifacts")
        print(f"  - Successfully enriched: {enrichment_result['enriched']} indicators")
        if enrichment_result['errors'] > 0:
            print(f"  - Errors: {enrichment_result['errors']}")
        
        if args.json:
            print("\nDetailed results:")
            print(json.dumps(enrichment_result, indent=2))
        elif log_level == "debug":
            for detail in enrichment_result['details']:
                logging.debug("Enrichment detail: %s", detail)
        
    except ConfigurationError as e:
        parser.error(f"Configuration error: {e}")
    except Exception as e:
        parser.error(f"Error: {e}")


if __name__ == "__main__":
    cli()