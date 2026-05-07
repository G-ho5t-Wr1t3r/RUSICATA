from django.urls import path
from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("api/stats/", views.dashboard_stats, name="dashboard_stats"),
    path("service/<int:service_id>/", views.service_rules, name="service_rules"),
    path("toggle-rule/<str:rule_type>/<int:rule_id>/", views.toggle_rule, name="toggle_rule"),
    path("toggle-all/<int:service_id>/<str:action>/", views.toggle_all_rules, name="toggle_all_rules"),
    path("add-http/<int:service_id>/", views.add_http_rule, name="add_http_rule"),
    path("add-transport/<int:service_id>/", views.add_transport_rule, name="add_transport_rule"),
    path("delete-rule/<str:rule_type>/<int:rule_id>/", views.delete_rule, name="delete_rule"),
    path("add-service/", views.add_service, name="add_service"),
    path("old_index/", views.index, name="index"),
]
