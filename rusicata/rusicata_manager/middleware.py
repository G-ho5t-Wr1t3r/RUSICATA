from django.http import HttpResponseForbidden
from django.conf import settings

class TeamIPWhitelistMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = request.META.get('REMOTE_ADDR')
        if ip not in settings.TEAM_ALLOWED_IPS:
            return HttpResponseForbidden('Accesso negato - solo membri del team')
        return self.get_response(request)