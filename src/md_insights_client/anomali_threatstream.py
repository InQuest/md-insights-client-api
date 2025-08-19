#!/usr/bin/env python3
"""
Anomali ThreatStream integration for MD Insights Client.
Pushes OPSWAT MD Insights enrichment data to Anomali ThreatStream.
"""

import ipaddress
import json
import logging
import os
from typing import Dict, Any, Optional, Union

import requests


logger = logging.getLogger(__name__)


class ThreatStreamClient:
    """Client for interacting with Anomali ThreatStream API."""
    
    def __init__(self, api_key: str = None, base_url: str = None, 
                 source_name: str = None, tlp: str = None):
        """
        Initialize ThreatStream client.
        
        Args:
            api_key: API key in format 'username:apikey'
            base_url: Base URL for ThreatStream API
            source_name: Source name for enrichments in ThreatStream
            tlp: Traffic Light Protocol setting for shared intelligence
        """
        self.api_key = api_key or os.getenv('ANOMALI_API')
        self.base_url = base_url or os.getenv('ANOMALI_URL', 'https://api.threatstream.com/api/v2')
        self.source_name = source_name or os.getenv('ANOMALI_SOURCE', 'OPSWAT_MDInSights')
        self.tlp = tlp or os.getenv('ANOMALI_TLP', 'amber')
        
        if not self.api_key:
            raise ValueError("ThreatStream API key required (set ANOMALI_API or pass api_key)")
        
        self.headers = {
            'Authorization': f'apikey {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def _get_indicator_type(self, ioc: str) -> str:
        """Determine indicator type for IOC."""
        try:
            ip = ipaddress.ip_address(ioc)
            return 'ip' if ip.version == 4 else 'ipv6'
        except ValueError:
            return 'domain'
    
    def get_or_create_indicator(self, ioc_value: str, 
                                confidence: int = 50,
                                severity: str = 'medium') -> Optional[int]:
        """
        Get existing indicator or create new one.
        
        Args:
            ioc_value: The IOC value (IP or domain)
            confidence: Confidence score (0-100)
            severity: Severity level
            
        Returns:
            Indicator ID if successful, None otherwise
        """
        # Search for existing indicator
        try:
            response = self.session.get(
                f'{self.base_url}/intelligence/',
                params={'value': ioc_value, 'limit': 1},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get('objects'):
                indicator_id = data['objects'][0]['id']
                logger.info(f"Found existing indicator {indicator_id} for {ioc_value}")
                return indicator_id
        except requests.exceptions.RequestException as e:
            logger.error(f"Error searching for indicator: {e}")
            return None
        
        # Create new indicator
        itype = self._get_indicator_type(ioc_value)
        
        # Map insights data to ThreatStream indicator types
        itype_mapping = {
            'ip': 'mal_ip',
            'ipv6': 'mal_ip',
            'domain': 'mal_domain'
        }
        
        body = {
            'value': ioc_value,
            'itype': itype_mapping.get(itype, itype),
            'source': self.source_name,
            'classification': 'private',
            'confidence': confidence,
            'severity': severity,
            'status': 'active',
            'tags': [{'name': 'md-insights', 'tlp': self.tlp}]
        }
        
        try:
            response = self.session.post(
                f'{self.base_url}/intelligence/import/',
                json=body,
                timeout=30
            )
            response.raise_for_status()
            result = response.json()
            
            if result.get('import_session_id'):
                logger.info(f"Created import session {result['import_session_id']} for {ioc_value}")
                # Note: In production, you'd want to poll for completion
                # For now, we'll just return the session ID
                return result.get('import_session_id')
        except requests.exceptions.RequestException as e:
            logger.error(f"Error creating indicator: {e}")
            return None
    
    def add_enrichment(self, indicator_id: int, enrichment_data: Dict[str, Any]) -> bool:
        """
        Add enrichment data as tags/attributes to an indicator.
        
        Args:
            indicator_id: ThreatStream indicator ID
            enrichment_data: Dictionary of enrichment data
            
        Returns:
            True if successful, False otherwise
        """
        tags = []
        
        # Process MD Insights enrichment data
        if enrichment_data.get('reputation'):
            rep = enrichment_data['reputation']
            
            # Add reputation score as tag
            if rep.get('score'):
                tags.append({
                    'name': f"md-insights-reputation-{rep['score']}",
                    'tlp': self.tlp
                })
            
            # Process InQuest data
            if rep.get('report', {}).get('inquest', {}).get('malicious'):
                tags.append({
                    'name': 'md-insights-malicious',
                    'tlp': self.tlp
                })
                
                # Add sources
                for source in rep.get('report', {}).get('inquest', {}).get('sources', []):
                    tags.append({
                        'name': f'md-insights-source-{source}',
                        'tlp': self.tlp
                    })
        
        # Process C2 data
        if enrichment_data.get('c2'):
            c2_value = enrichment_data['c2']
            if c2_value and c2_value != 'null':
                tags.append({
                    'name': f'md-insights-c2-{c2_value.replace(" ", "_").replace(".", "")}',
                    'tlp': self.tlp
                })
        
        if not tags:
            logger.info("No enrichment data to add")
            return True
        
        # Update indicator with tags
        body = {
            'tags': tags
        }
        
        try:
            response = self.session.patch(
                f'{self.base_url}/intelligence/{indicator_id}/',
                json=body,
                timeout=30
            )
            response.raise_for_status()
            logger.info(f"Added {len(tags)} enrichment tags to indicator {indicator_id}")
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Error adding enrichment: {e}")
            return False


def process_insights_enrichment(insights_data: Dict[str, Any], 
                               threatstream_client: ThreatStreamClient) -> Dict[str, Any]:
    """
    Process MD Insights data and push to ThreatStream.
    
    Args:
        insights_data: Response from MD Insights API
        threatstream_client: ThreatStream client instance
        
    Returns:
        Dictionary with processing results
    """
    results = {
        'processed': 0,
        'enriched': 0,
        'errors': 0,
        'details': []
    }
    
    if not insights_data.get('results'):
        logger.warning("No results in MD Insights data")
        return results
    
    for ioc_value, ioc_data in insights_data['results'].items():
        results['processed'] += 1
        
        # Determine confidence based on reputation score
        confidence = 50  # default
        severity = 'medium'  # default
        
        if ioc_data.get('reputation'):
            score = ioc_data['reputation'].get('score', 0)
            if score >= 8:
                confidence = 90
                severity = 'high'
            elif score >= 5:
                confidence = 70
                severity = 'medium'
            elif score >= 3:
                confidence = 50
                severity = 'low'
            else:
                confidence = 30
                severity = 'low'
        
        # Check if there's malicious indication
        if ioc_data.get('reputation', {}).get('report', {}).get('inquest', {}).get('malicious'):
            confidence = max(confidence, 80)
            severity = 'high'
        
        # Check for C2 data
        if ioc_data.get('c2') and ioc_data['c2'] != 'null':
            confidence = max(confidence, 85)
            severity = 'high'
        
        # Get or create indicator in ThreatStream
        indicator_id = threatstream_client.get_or_create_indicator(
            ioc_value, 
            confidence=confidence,
            severity=severity
        )
        
        if indicator_id:
            # Add enrichment data
            success = threatstream_client.add_enrichment(indicator_id, ioc_data)
            
            if success:
                results['enriched'] += 1
                results['details'].append({
                    'ioc': ioc_value,
                    'indicator_id': indicator_id,
                    'status': 'enriched'
                })
                logger.info(f"Successfully enriched {ioc_value} (ID: {indicator_id})")
            else:
                results['errors'] += 1
                results['details'].append({
                    'ioc': ioc_value,
                    'indicator_id': indicator_id,
                    'status': 'enrichment_failed'
                })
        else:
            results['errors'] += 1
            results['details'].append({
                'ioc': ioc_value,
                'status': 'creation_failed'
            })
    
    return results