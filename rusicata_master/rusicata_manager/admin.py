from django.contrib import admin
from .models import Service, HttpRule

class HttpRuleAdmin(admin.ModelAdmin):
    exclude = ('sid',)
    list_filter = ('service', 'action', 'request_method', 'content_location',)

admin.site.register(Service)
admin.site.register(HttpRule, HttpRuleAdmin)
