from django.urls import path
from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("api/stats/", views.dashboard_stats, name="dashboard_stats"),
    path("api/service-rules/<int:service_id>/", views.service_rules_api, name="service_rules_api"),
    path("api/rule-detail/<str:rule_type>/<int:rule_id>/", views.rule_detail_api, name="rule_detail_api"),
    path("api/edit-rule/<str:rule_type>/<int:rule_id>/", views.edit_rule_api, name="edit_rule_api"),
    path("service/<int:service_id>/", views.service_rules, name="service_rules"),
    path("toggle-rule/<str:rule_type>/<int:rule_id>/", views.toggle_rule, name="toggle_rule"),
    path("toggle-all/<int:service_id>/<str:action>/", views.toggle_all_rules, name="toggle_all_rules"),
    path("add-http-rule/<int:service_id>/", views.add_http_rule, name="add_http_rule"),
    path("add-transport-rule/<int:service_id>/", views.add_transport_rule, name="add_transport_rule"),
    path("delete-rule/<str:rule_type>/<int:rule_id>/", views.delete_rule, name="delete_rule"),
    path("add-service/", views.add_service, name="add_service"),
    path("edit-service/<int:service_id>/", views.edit_service, name="edit_service"),
    path("api/service-detail/<int:service_id>/", views.service_detail_api, name="service_detail_api"),
    path("bulk-add-services/", views.bulk_add_services, name="bulk_add_services"),
    path("delete-service/<int:service_id>/", views.delete_service, name="delete_service"),
    path("create-analyst/", views.create_analyst, name="create_analyst"),
    path("old_index/", views.index, name="index"),
]
