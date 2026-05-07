from django.test import TestCase
from .models import Service, HttpRule
import os
from unittest.mock import patch
import shutil

class HttpRuleActiveTest(TestCase):
    def setUp(self):
        # Create a mock directory for rules
        self.test_rules_dir = '/tmp/suricata_rules/'
        os.makedirs(self.test_rules_dir, exist_ok=True)
        
        # Create a mock directory for config
        self.test_config_dir = '/tmp/suricata_config/'
        os.makedirs(self.test_config_dir, exist_ok=True)
        
        # Patch RULES_BASE_PATH and CONFIG_BASE_PATH to avoid side effects on system
        self.rules_patcher = patch('rusicata_manager.models.RULES_BASE_PATH', self.test_rules_dir)
        self.config_patcher = patch('rusicata_manager.models.CONFIG_BASE_PATH', self.test_config_dir)
        self.hot_reload_patcher = patch('rusicata_manager.models.suricata_hot_reload')
        self.daemon_reload_patcher = patch('rusicata_manager.models.suricata_deamon_reload')
        
        self.mock_rules_path = self.rules_patcher.start()
        self.mock_config_path = self.config_patcher.start()
        self.mock_hot_reload = self.hot_reload_patcher.start()
        self.mock_daemon_reload = self.daemon_reload_patcher.start()
        
        # Create suricata.yaml in mock config path
        with open(os.path.join(self.test_config_dir, 'suricata.yaml'), 'w') as f:
            f.write('%YAML 1.1\n---\nrule-files: []\n')

        self.service = Service.objects.create(name="test_service", port=8080)

    def tearDown(self):
        self.rules_patcher.stop()
        self.config_patcher.stop()
        self.hot_reload_patcher.stop()
        self.daemon_reload_patcher.stop()
        # Clean up /tmp
        shutil.rmtree(self.test_rules_dir, ignore_errors=True)
        shutil.rmtree(self.test_config_dir, ignore_errors=True)

    def test_http_rule_is_active_default(self):
        rule = HttpRule.objects.create(
            service=self.service,
            protocol='http',
            action='alert',
            message='test message',
            request_method='GET',
            content='test_content',
            content_location='http_uri'
        )
        # This will fail because is_active is not yet defined
        self.assertTrue(getattr(rule, 'is_active', False), "is_active should exist and be True by default")
        
        # Check if written to file
        file_path = os.path.join(self.test_rules_dir, 'test_service.rules')
        with open(file_path, 'r') as f:
            content = f.read()
        self.assertIn('test_content', content)
        self.assertIn(f'sid:{rule.sid};', content)

    def test_http_rule_inactive_not_written(self):
        # This will fail because HttpRule does not accept is_active argument
        try:
            rule = HttpRule.objects.create(
                service=self.service,
                protocol='http',
                action='alert',
                message='test message',
                request_method='GET',
                content='inactive_content',
                content_location='http_uri',
                is_active=False
            )
        except TypeError:
            self.fail("HttpRule.objects.create() failed, probably because 'is_active' is missing")
            
        self.assertFalse(rule.is_active)
        
        # Check if NOT written to file
        file_path = os.path.join(self.test_rules_dir, 'test_service.rules')
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                content = f.read()
            self.assertNotIn('inactive_content', content)

    def test_http_rule_toggle_active(self):
        rule = HttpRule.objects.create(
            service=self.service,
            protocol='http',
            action='alert',
            message='test message',
            request_method='GET',
            content='toggle_content',
            content_location='http_uri'
        )
        
        file_path = os.path.join(self.test_rules_dir, 'test_service.rules')
        with open(file_path, 'r') as f:
            content = f.read()
        self.assertIn('toggle_content', content)
        
        # Toggle to inactive
        rule.is_active = False
        rule.save()
        
        with open(file_path, 'r') as f:
            content = f.read()
        self.assertNotIn('toggle_content', content)
        
        # Toggle back to active
        rule.is_active = True
        rule.save()
        
        with open(file_path, 'r') as f:
            content = f.read()
        self.assertIn('toggle_content', content)
