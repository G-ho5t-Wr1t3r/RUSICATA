from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User

class DashboardViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='password')
        self.url = reverse('dashboard')

    def test_dashboard_access_denied_anonymous(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_dashboard_access_allowed_authenticated(self):
        self.client.login(username='testuser', password='password')
        response = self.client.get(self.url)
        # It might fail with 404 because template doesn't exist yet, but we want to see it fail correctly
        self.assertEqual(response.status_code, 200)

    def test_dashboard_context_data(self):
        self.client.login(username='testuser', password='password')
        response = self.client.get(self.url)
        self.assertIn('status', response.context)
        self.assertIn('stats', response.context)
        self.assertIn('recent_events', response.context)
