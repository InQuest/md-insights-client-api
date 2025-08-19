"""Tests for Anomali ThreatStream integration."""

import json
import unittest
from unittest.mock import MagicMock, patch, call

from md_insights_client.anomali_threatstream import (
    ThreatStreamClient,
    process_insights_enrichment,
)


class TestThreatStreamClient(unittest.TestCase):
    """Test ThreatStreamClient class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.api_key = "testuser:testapikey"
        self.base_url = "https://api.test.com/api/v2"
        self.client = ThreatStreamClient(
            api_key=self.api_key,
            base_url=self.base_url,
            source_name="TEST_SOURCE",
            tlp="amber"
        )
    
    def test_init_with_env_vars(self):
        """Test initialization with environment variables."""
        with patch.dict('os.environ', {
            'ANOMALI_API': 'envuser:envapikey',
            'ANOMALI_URL': 'https://env.test.com',
            'ANOMALI_SOURCE': 'ENV_SOURCE',
            'ANOMALI_TLP': 'red'
        }):
            client = ThreatStreamClient()
            self.assertEqual(client.api_key, 'envuser:envapikey')
            self.assertEqual(client.base_url, 'https://env.test.com')
            self.assertEqual(client.source_name, 'ENV_SOURCE')
            self.assertEqual(client.tlp, 'red')
    
    def test_init_without_api_key_raises_error(self):
        """Test that initialization without API key raises ValueError."""
        with self.assertRaises(ValueError) as context:
            ThreatStreamClient(api_key=None)
        self.assertIn("ThreatStream API key required", str(context.exception))
    
    def test_get_indicator_type_ipv4(self):
        """Test indicator type detection for IPv4."""
        self.assertEqual(self.client._get_indicator_type("192.168.1.1"), "ip")
        self.assertEqual(self.client._get_indicator_type("8.8.8.8"), "ip")
    
    def test_get_indicator_type_ipv6(self):
        """Test indicator type detection for IPv6."""
        self.assertEqual(
            self.client._get_indicator_type("2001:db8::1"),
            "ipv6"
        )
    
    def test_get_indicator_type_domain(self):
        """Test indicator type detection for domain."""
        self.assertEqual(
            self.client._get_indicator_type("example.com"),
            "domain"
        )
        self.assertEqual(
            self.client._get_indicator_type("subdomain.example.com"),
            "domain"
        )
    
    @patch('md_insights_client.anomali_threatstream.requests.Session')
    def test_get_existing_indicator(self, mock_session_class):
        """Test getting an existing indicator."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        
        # Mock successful response with existing indicator
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'objects': [{'id': 12345, 'value': '192.168.1.1'}]
        }
        mock_session.get.return_value = mock_response
        
        client = ThreatStreamClient(api_key=self.api_key)
        indicator_id = client.get_or_create_indicator('192.168.1.1')
        
        self.assertEqual(indicator_id, 12345)
        mock_session.get.assert_called_once()
    
    @patch('md_insights_client.anomali_threatstream.requests.Session')
    def test_create_new_indicator(self, mock_session_class):
        """Test creating a new indicator."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        
        # Mock empty search response (no existing indicator)
        mock_search_response = MagicMock()
        mock_search_response.json.return_value = {'objects': []}
        
        # Mock successful create response
        mock_create_response = MagicMock()
        mock_create_response.json.return_value = {
            'import_session_id': '54321'
        }
        
        mock_session.get.return_value = mock_search_response
        mock_session.post.return_value = mock_create_response
        
        client = ThreatStreamClient(api_key=self.api_key)
        result = client.get_or_create_indicator(
            'malicious.example.com',
            confidence=80,
            severity='high'
        )
        
        self.assertEqual(result, '54321')
        mock_session.post.assert_called_once()
        
        # Verify the POST data
        call_args = mock_session.post.call_args
        self.assertIn('json', call_args.kwargs)
        post_data = call_args.kwargs['json']
        self.assertEqual(post_data['value'], 'malicious.example.com')
        self.assertEqual(post_data['itype'], 'mal_domain')
        self.assertEqual(post_data['confidence'], 80)
        self.assertEqual(post_data['severity'], 'high')


class TestProcessInsightsEnrichment(unittest.TestCase):
    """Test process_insights_enrichment function."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_client = MagicMock(spec=ThreatStreamClient)
        self.mock_client.tlp = 'amber'
        
    def test_process_empty_results(self):
        """Test processing empty results."""
        insights_data = {'results': {}}
        result = process_insights_enrichment(insights_data, self.mock_client)
        
        self.assertEqual(result['processed'], 0)
        self.assertEqual(result['enriched'], 0)
        self.assertEqual(result['errors'], 0)
    
    def test_process_malicious_domain(self):
        """Test processing a malicious domain."""
        insights_data = {
            'results': {
                'evil.example.com': {
                    'artifact_type': 'domain',
                    'reputation': {
                        'score': 8,
                        'report': {
                            'inquest': {
                                'malicious': True,
                                'sources': ['insights-ti']
                            }
                        }
                    },
                    'c2': None
                }
            }
        }
        
        # Mock successful indicator creation and enrichment
        self.mock_client.get_or_create_indicator.return_value = 100
        self.mock_client.add_enrichment.return_value = True
        
        result = process_insights_enrichment(insights_data, self.mock_client)
        
        self.assertEqual(result['processed'], 1)
        self.assertEqual(result['enriched'], 1)
        self.assertEqual(result['errors'], 0)
        
        # Verify indicator was created with high confidence
        self.mock_client.get_or_create_indicator.assert_called_once_with(
            'evil.example.com',
            confidence=80,  # Should be high due to malicious flag
            severity='high'
        )
    
    def test_process_c2_indicator(self):
        """Test processing a C2 indicator."""
        insights_data = {
            'results': {
                '192.168.1.1': {
                    'artifact_type': 'ip',
                    'reputation': {'score': 0},
                    'c2': 'APT 28'
                }
            }
        }
        
        self.mock_client.get_or_create_indicator.return_value = 200
        self.mock_client.add_enrichment.return_value = True
        
        result = process_insights_enrichment(insights_data, self.mock_client)
        
        self.assertEqual(result['processed'], 1)
        self.assertEqual(result['enriched'], 1)
        
        # Verify high confidence due to C2 data
        self.mock_client.get_or_create_indicator.assert_called_once_with(
            '192.168.1.1',
            confidence=85,
            severity='high'
        )
    
    def test_process_with_errors(self):
        """Test processing with errors."""
        insights_data = {
            'results': {
                'test.example.com': {
                    'artifact_type': 'domain',
                    'reputation': {'score': 5},
                    'c2': None
                }
            }
        }
        
        # Mock failed indicator creation
        self.mock_client.get_or_create_indicator.return_value = None
        
        result = process_insights_enrichment(insights_data, self.mock_client)
        
        self.assertEqual(result['processed'], 1)
        self.assertEqual(result['enriched'], 0)
        self.assertEqual(result['errors'], 1)
        self.assertEqual(result['details'][0]['status'], 'creation_failed')


if __name__ == '__main__':
    unittest.main()