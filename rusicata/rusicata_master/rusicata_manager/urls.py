from django.urls import path
from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("service/<int:service_id>/", views.service_rules, name="service_rules"),
    path("toggle-rule/<str:rule_type>/<int:rule_id>/", views.toggle_rule, name="toggle_rule"),
    path("toggle-all/<int:service_id>/<str:action>/", views.toggle_all_rules, name="toggle_all_rules"),
    path("old_index/", views.index, name="index"),
]
