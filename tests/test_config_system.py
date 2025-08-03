#!/usr/bin/env python3

import unittest
import tempfile
import shutil
import os
import yaml
from pathlib import Path
from unittest.mock import patch, Mock

from configs.config_loader import (load_configuration, get_target_configuration, 
                                 get_attack_model_configuration, save_configuration)
from configs.env_resolver import (resolve_environment_variables, validate_required_environment_variables,
                                generate_env_template)
from configs.auth_manager import (generate_auth_headers, validate_credentials)
from configs.api_providers import (format_openai_request, format_anthropic_request,
                                 get_request_formatter, get_response_parser)
from configs.validator import (validate_configuration_schema, validate_configuration_logic,
                              validate_environment_setup)
from configs.target_manager import (test_target_connectivity, list_targets_with_status)
from configs.migration import (create_default_config_from_template, get_migration_status)


class TestConfigSystem(unittest.TestCase):
    """Comprehensive tests for the configuration system."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.config_path = Path(self.test_dir) / "test_config.yaml"
        
        # Sample configuration for testing
        self.sample_config = {
            'version': '1.0',
            'global': {
                'timeout': {'connection': 30, 'read': 60, 'total': 120},
                'retry': {'attempts': 3, 'backoff': 'exponential', 'max_delay': 30}
            },
            'environments': {
                'development': {'log_level': 'DEBUG', 'rate_limit': 1},
                'production': {'log_level': 'INFO', 'rate_limit': 10}
            },
            'providers': {
                'test_openai': {
                    'type': 'openai',
                    'base_url': 'https://api.openai.com/v1/chat/completions',
                    'auth': {
                        'type': 'api_key',
                        'header': 'Authorization',
                        'format': 'Bearer ${OPENAI_API_KEY}'
                    },
                    'models': ['gpt-4', 'gpt-3.5-turbo']
                },
                'test_anthropic': {
                    'type': 'anthropic',
                    'base_url': 'https://api.anthropic.com/v1/messages',
                    'auth': {
                        'type': 'api_key',
                        'header': 'x-api-key',
                        'format': '${ANTHROPIC_API_KEY}'
                    },
                    'models': ['claude-3-opus-20240229']
                }
            },
            'targets': {
                'test_gpt4': {
                    'provider': 'test_openai',
                    'model': 'gpt-4',
                    'description': 'Test GPT-4 target'
                },
                'test_claude': {
                    'provider': 'test_anthropic',
                    'model': 'claude-3-opus-20240229',
                    'description': 'Test Claude target'
                }
            },
            'attack': {
                'attacker_model': {
                    'provider': 'test_openai',
                    'model': 'gpt-4',
                    'temperature': 0.7
                },
                'analyzer_model': {
                    'provider': 'test_openai',
                    'model': 'gpt-3.5-turbo',
                    'temperature': 0.3
                }
            }
        }
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def _save_test_config(self, config=None):
        """Helper to save test configuration."""
        config = config or self.sample_config
        with open(self.config_path, 'w') as f:
            yaml.dump(config, f)
        return str(self.config_path)
    
    # Configuration Loading Tests
    
    def test_load_configuration_success(self):
        """Test successful configuration loading."""
        config_path = self._save_test_config()
        
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key', 'ANTHROPIC_API_KEY': 'test-key'}):
            config = load_configuration(config_path)
            
            self.assertEqual(config['version'], '1.0')
            self.assertIn('providers', config)
            self.assertIn('targets', config)
    
    def test_load_configuration_file_not_found(self):
        """Test configuration loading with missing file."""
        with self.assertRaises(FileNotFoundError):
            load_configuration('/nonexistent/path/config.yaml')
    
    def test_load_configuration_invalid_yaml(self):
        """Test configuration loading with invalid YAML."""
        with open(self.config_path, 'w') as f:
            f.write("invalid: yaml: content: [")
        
        with self.assertRaises(yaml.YAMLError):
            load_configuration(str(self.config_path))
    
    def test_get_target_configuration(self):
        """Test getting target configuration."""
        config_path = self._save_test_config()
        
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}):
            config = load_configuration(config_path)
            target_config = get_target_configuration(config, 'test_gpt4')
            
            self.assertEqual(target_config['model'], 'gpt-4')
            self.assertEqual(target_config['type'], 'openai')
            self.assertIn('auth', target_config)
    
    def test_get_target_configuration_not_found(self):
        """Test getting non-existent target configuration."""
        config_path = self._save_test_config()
        
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}):
            config = load_configuration(config_path)
            
            with self.assertRaises(ValueError):
                get_target_configuration(config, 'nonexistent_target')
    
    def test_get_attack_model_configuration(self):
        """Test getting attack model configuration."""
        config_path = self._save_test_config()
        
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}):
            config = load_configuration(config_path)
            attack_config = get_attack_model_configuration(config, 'attacker_model')
            
            self.assertEqual(attack_config['model'], 'gpt-4')
            self.assertEqual(attack_config['temperature'], 0.7)
    
    # Environment Variable Resolution Tests
    
    def test_resolve_environment_variables(self):
        """Test environment variable resolution."""
        with patch.dict(os.environ, {'TEST_VAR': 'test_value'}):
            result = resolve_environment_variables('${TEST_VAR}')
            self.assertEqual(result, 'test_value')
    
    def test_resolve_environment_variables_missing(self):
        """Test environment variable resolution with missing variable."""
        with self.assertRaises(ValueError):
            resolve_environment_variables('${MISSING_VAR}')
    
    def test_validate_required_environment_variables(self):
        """Test validation of required environment variables."""
        config = {'test': '${REQUIRED_VAR}'}
        
        with patch.dict(os.environ, {}, clear=True):
            missing = validate_required_environment_variables(config)
            self.assertEqual(missing, ['REQUIRED_VAR'])
        
        with patch.dict(os.environ, {'REQUIRED_VAR': 'value'}):
            missing = validate_required_environment_variables(config)
            self.assertEqual(missing, [])
    
    def test_generate_env_template(self):
        """Test environment template generation."""
        config = {'test1': '${VAR1}', 'test2': '${VAR2}'}
        template = generate_env_template(config)
        
        self.assertIn('VAR1=your_value_here', template)
        self.assertIn('VAR2=your_value_here', template)
    
    # Authentication Manager Tests
    
    def test_generate_auth_headers_api_key(self):
        """Test API key authentication header generation."""
        auth_config = {
            'type': 'api_key',
            'header': 'Authorization',
            'format': 'Bearer test-key'
        }
        
        headers = generate_auth_headers(auth_config)
        self.assertEqual(headers, {'Authorization': 'Bearer test-key'})
    
    def test_generate_auth_headers_bearer(self):
        """Test bearer token authentication header generation."""
        auth_config = {
            'type': 'bearer',
            'token': 'test-token'
        }
        
        headers = generate_auth_headers(auth_config)
        self.assertEqual(headers, {'Authorization': 'Bearer test-token'})
    
    def test_generate_auth_headers_custom(self):
        """Test custom authentication header generation."""
        auth_config = {
            'type': 'custom',
            'headers': {
                'X-API-Key': 'test-key',
                'X-Client-ID': 'test-client'
            }
        }
        
        headers = generate_auth_headers(auth_config)
        expected = {'X-API-Key': 'test-key', 'X-Client-ID': 'test-client'}
        self.assertEqual(headers, expected)
    
    def test_validate_credentials_valid(self):
        """Test credential validation with valid credentials."""
        auth_config = {
            'type': 'api_key',
            'header': 'Authorization',
            'format': 'Bearer test-key'
        }
        
        result = validate_credentials(auth_config)
        self.assertTrue(result['valid'])
    
    def test_validate_credentials_invalid(self):
        """Test credential validation with invalid credentials."""
        auth_config = {
            'type': 'unsupported_type'
        }
        
        result = validate_credentials(auth_config)
        self.assertFalse(result['valid'])
        self.assertIn('error', result)
    
    # API Provider Tests
    
    def test_format_openai_request(self):
        """Test OpenAI request formatting."""
        prompt = "Test prompt"
        model_params = {
            'model': 'gpt-4',
            'temperature': 0.7,
            'max_tokens': 1000
        }
        
        result = format_openai_request(prompt, model_params)
        
        expected = {
            'model': 'gpt-4',
            'messages': [{'role': 'user', 'content': 'Test prompt'}],
            'temperature': 0.7,
            'max_tokens': 1000
        }
        self.assertEqual(result, expected)
    
    def test_format_anthropic_request(self):
        """Test Anthropic request formatting."""
        prompt = "Test prompt"
        model_params = {
            'model': 'claude-3-opus-20240229',
            'temperature': 0.7,
            'max_tokens': 1000
        }
        
        result = format_anthropic_request(prompt, model_params)
        
        expected = {
            'model': 'claude-3-opus-20240229',
            'max_tokens': 1000,
            'messages': [{'role': 'user', 'content': 'Test prompt'}],
            'temperature': 0.7
        }
        self.assertEqual(result, expected)
    
    def test_get_request_formatter(self):
        """Test request formatter retrieval."""
        openai_formatter = get_request_formatter('openai')
        self.assertEqual(openai_formatter, format_openai_request)
        
        anthropic_formatter = get_request_formatter('anthropic')
        self.assertEqual(anthropic_formatter, format_anthropic_request)
        
        with self.assertRaises(ValueError):
            get_request_formatter('unsupported_provider')
    
    def test_get_response_parser(self):
        """Test response parser retrieval."""
        openai_parser = get_response_parser('openai')
        self.assertIsNotNone(openai_parser)
        
        anthropic_parser = get_response_parser('anthropic')
        self.assertIsNotNone(anthropic_parser)
        
        with self.assertRaises(ValueError):
            get_response_parser('unsupported_provider')
    
    # Configuration Validation Tests
    
    def test_validate_configuration_schema_valid(self):
        """Test configuration schema validation with valid config."""
        validated_config = validate_configuration_schema(self.sample_config)
        self.assertEqual(validated_config, self.sample_config)
    
    def test_validate_configuration_schema_invalid(self):
        """Test configuration schema validation with invalid config."""
        invalid_config = {'version': '1.0'}  # Missing required fields
        
        with self.assertRaises(ValueError):
            validate_configuration_schema(invalid_config)
    
    def test_validate_configuration_logic(self):
        """Test configuration business logic validation."""
        errors = validate_configuration_logic(self.sample_config)
        self.assertEqual(errors, [])  # Should be no errors for valid config
    
    def test_validate_configuration_logic_invalid_reference(self):
        """Test configuration logic validation with invalid target reference."""
        invalid_config = self.sample_config.copy()
        invalid_config['targets']['invalid_target'] = {
            'provider': 'nonexistent_provider',
            'model': 'test-model',
            'description': 'Invalid target'
        }
        
        errors = validate_configuration_logic(invalid_config)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any('nonexistent_provider' in error for error in errors))
    
    def test_validate_environment_setup(self):
        """Test environment setup validation."""
        config_path = self._save_test_config()
        
        with patch.dict(os.environ, {}, clear=True):
            config = load_configuration(config_path)
            result = validate_environment_setup(config)
            
            self.assertFalse(result['valid'])
            self.assertGreater(len(result['missing_variables']), 0)
    
    # Target Manager Tests
    
    @patch('configs.target_manager.requests.head')
    def test_test_target_connectivity_success(self, mock_head):
        """Test successful target connectivity test."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.elapsed.total_seconds.return_value = 0.5
        mock_head.return_value = mock_response
        
        config_path = self._save_test_config()
        
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}):
            config = load_configuration(config_path)
            result = test_target_connectivity(config, 'test_gpt4')
            
            self.assertEqual(result['status'], 'success')
            self.assertEqual(result['response_time'], 0.5)
            self.assertIsNone(result['error'])
    
    @patch('configs.target_manager.requests.head')
    def test_test_target_connectivity_failure(self, mock_head):
        """Test failed target connectivity test."""
        mock_head.side_effect = Exception("Connection failed")
        
        config_path = self._save_test_config()
        
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}):
            config = load_configuration(config_path)
            result = test_target_connectivity(config, 'test_gpt4')
            
            self.assertEqual(result['status'], 'failed')
            self.assertIn('Connection failed', result['error'])
    
    @patch('configs.target_manager.test_target_connectivity')
    def test_list_targets_with_status(self, mock_test):
        """Test listing targets with status."""
        mock_test.return_value = {
            'status': 'success',
            'response_time': 0.5,
            'error': None
        }
        
        config_path = self._save_test_config()
        
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key', 'ANTHROPIC_API_KEY': 'test-key'}):
            config = load_configuration(config_path)
            targets = list_targets_with_status(config)
            
            self.assertEqual(len(targets), 2)
            self.assertEqual(targets[0]['name'], 'test_gpt4')
            self.assertEqual(targets[0]['status'], 'success')
    
    # Migration Tests
    
    def test_create_default_config_from_template(self):
        """Test creating default configuration from template."""
        with patch('configs.migration.get_default_config_path', return_value=str(self.config_path)):
            result = create_default_config_from_template('openai')
            
            self.assertTrue(result['success'])
            self.assertEqual(result['template_used'], 'openai')
            self.assertTrue(self.config_path.exists())
    
    def test_create_default_config_invalid_template(self):
        """Test creating default configuration with invalid template."""
        result = create_default_config_from_template('nonexistent_template')
        
        self.assertFalse(result['success'])
        self.assertIn('available_templates', result)
    
    def test_get_migration_status_no_config(self):
        """Test migration status with no configuration."""
        with patch('configs.migration.get_default_config_path', return_value='/nonexistent/config.yaml'), \
             patch('configs.migration.Path.exists', return_value=False):
            
            status = get_migration_status()
            self.assertEqual(status['status'], 'no_config')
            self.assertFalse(status['has_new_config'])
    
    # Integration Tests
    
    def test_end_to_end_configuration_workflow(self):
        """Test complete configuration workflow."""
        # Create configuration from template
        with patch('configs.migration.get_default_config_path', return_value=str(self.config_path)):
            result = create_default_config_from_template('openai')
            self.assertTrue(result['success'])
        
        # Load and validate configuration
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}):
            config = load_configuration(str(self.config_path))
            self.assertIsNotNone(config)
            
            # Test target configuration retrieval
            target_names = list(config['targets'].keys())
            if target_names:
                target_config = get_target_configuration(config, target_names[0])
                self.assertIsNotNone(target_config)
            
            # Test attack model configuration
            attack_config = get_attack_model_configuration(config, 'attacker_model')
            self.assertIsNotNone(attack_config)
    
    def test_configuration_with_different_environments(self):
        """Test configuration loading with different environments."""
        config_path = self._save_test_config()
        
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key', 'ANTHROPIC_API_KEY': 'test-key'}):
            # Test development environment
            dev_config = load_configuration(config_path, environment='development')
            self.assertEqual(dev_config['global']['log_level'], 'DEBUG')
            
            # Test production environment
            prod_config = load_configuration(config_path, environment='production')
            self.assertEqual(prod_config['global']['log_level'], 'INFO')
    
    def test_configuration_save_and_reload(self):
        """Test saving and reloading configuration."""
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key', 'ANTHROPIC_API_KEY': 'test-key'}):
            # Save configuration
            save_configuration(self.sample_config, str(self.config_path))
            
            # Reload and verify
            reloaded_config = load_configuration(str(self.config_path))
            
            # Remove metadata for comparison
            reloaded_config.pop('_metadata', None)
            
            self.assertEqual(reloaded_config['version'], self.sample_config['version'])
            self.assertEqual(len(reloaded_config['providers']), len(self.sample_config['providers']))
            self.assertEqual(len(reloaded_config['targets']), len(self.sample_config['targets']))


if __name__ == '__main__':
    unittest.main()