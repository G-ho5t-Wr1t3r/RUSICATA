import json
import os
import tempfile
import shutil
from unittest.mock import patch
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from rusicata_manager.models import Service, HttpRule

class EndToEndTest(TestCase):
    def setUp(self):
        # Setup mock directories
        self.test_rules_dir = tempfile.mkdtemp()
        self.test_config_dir = tempfile.mkdtemp()
        
        # Patch models constants and functions
        self.patches = [
            patch('rusicata_manager.models.RULES_BASE_PATH', self.test_rules_dir + '/'),
            patch('rusicata_manager.models.CONFIG_BASE_PATH', self.test_config_dir + '/'),
            patch('rusicata_manager.models.suricata_hot_reload'),
            patch('rusicata_manager.models.suricata_deamon_reload'),
            patch('rusicata_manager.models.load_suricata_config', return_value={'rule-files': []}),
            patch('rusicata_manager.models.dump_suricata_config'),
        ]
        for p in self.patches:
            p.start()

        self.user = User.objects.create_superuser(username='admin', password='password', email='admin@test.com')
        self.client = Client()
        self.client.login(username='admin', password='password')
        
        # Now we can safely create models
        self.service = Service.objects.create(name="web_service", port=80)
        self.rule = HttpRule.objects.create(
            service=self.service,
            protocol='http',
            action='alert',
            message='Malicious request',
            request_method='GET',
            content='malicious',
            content_location='http_uri'
        )
        
        # Mock eve.json for telemetry
        self.temp_eve = tempfile.NamedTemporaryFile(delete=False, mode='w')
        sample_event = {
            "timestamp": "2026-05-04T15:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "proto": "TCP",
            "alert": {"action": "blocked", "signature": "Malicious request"}
        }
        self.temp_eve.write(json.dumps(sample_event) + '\n')
        self.temp_eve.close()
        
        # Patch telemetry path
        import rusicata_manager.telemetry
        self.old_eve_path = rusicata_manager.telemetry.DEFAULT_EVE_PATH
        rusicata_manager.telemetry.DEFAULT_EVE_PATH = self.temp_eve.name

    def tearDown(self):
        import rusicata_manager.telemetry
        rusicata_manager.telemetry.DEFAULT_EVE_PATH = self.old_eve_path
        
        for p in self.patches:
            p.stop()
            
        shutil.rmtree(self.test_rules_dir)
        shutil.rmtree(self.test_config_dir)
        if os.path.exists(self.temp_eve.name):
            os.remove(self.temp_eve.name)

    def test_dashboard_access(self):
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Rusicata Dashboard")
        self.assertContains(response, "web_service")
        self.assertContains(response, "Malicious request")

    def test_toggle_rule(self):
        self.assertTrue(self.rule.is_active)
        response = self.client.get(reverse('toggle_rule', args=['http', self.rule.id]))
        self.assertEqual(response.status_code, 302) # Redirect
        
        self.rule.refresh_from_db()
        self.assertFalse(self.rule.is_active)

    def test_service_rules_view(self):
        response = self.client.get(reverse('service_rules', args=[self.service.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "malicious")
