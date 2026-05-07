from django.contrib import admin
from .models import Service, HttpRule, TransportLevelRule, GlobalRule

class HttpRuleAdmin(admin.ModelAdmin):
    exclude = ('sid',)
    list_filter = ('service', 'action', 'request_method', 'content_location',)

class TransportLevelRuleAdmin(admin.ModelAdmin):
    exclude = ('sid',)
    list_filter = ('service', 'action', 'protocol', 'flow_direction',)

class GlobalRuleAdmin(admin.ModelAdmin):
    exclude = ('sid',)
    list_filter = ('action', 'protocol', 'is_regex', 'is_active',)

admin.site.register(Service)
admin.site.register(HttpRule, HttpRuleAdmin)
admin.site.register(TransportLevelRule, TransportLevelRuleAdmin)
admin.site.register(GlobalRule, GlobalRuleAdmin)
