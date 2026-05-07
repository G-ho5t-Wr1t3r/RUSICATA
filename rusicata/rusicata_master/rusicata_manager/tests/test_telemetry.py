import json
import os
import tempfile
from django.test import TestCase
from rusicata_manager.telemetry import get_stats, get_recent_events

class TelemetryTest(TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w')
        self.sample_data = [
            {"timestamp":"2024-05-04T12:00:01Z", "event_type":"alert", "proto":"TCP", "alert":{"action":"blocked", "signature":"Test alert 1"}},
            {"timestamp":"2024-05-04T12:00:02Z", "event_type":"http", "proto":"TCP", "app_proto":"http"},
            {"timestamp":"2024-05-04T12:00:03Z", "event_type":"alert", "proto":"UDP", "alert":{"action":"allowed", "signature":"Test alert 2"}},
            {"timestamp":"2024-05-04T12:00:04Z", "event_type":"alert", "proto":"TCP", "alert":{"action":"blocked", "signature":"Test alert 3"}}
        ]
        for entry in self.sample_data:
            self.temp_file.write(json.dumps(entry) + '\n')
        self.temp_file.close()

    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    def test_get_stats(self):
        stats = get_stats(self.temp_file.name)
        self.assertEqual(stats['actions']['blocked'], 2)
        self.assertEqual(stats['actions']['allowed'], 1)
        self.assertEqual(stats['protocols']['TCP'], 3)
        self.assertEqual(stats['protocols']['UDP'], 1)
        self.assertEqual(stats['protocols']['HTTP'], 1)

    def test_get_recent_events(self):
        events = get_recent_events(n=2, file_path=self.temp_file.name)
        self.assertEqual(len(events), 2)
        # Order should be newest first (reverse order of file)
        self.assertEqual(events[0]['message'], "Test alert 3")
        self.assertEqual(events[1]['message'], "Test alert 2")
