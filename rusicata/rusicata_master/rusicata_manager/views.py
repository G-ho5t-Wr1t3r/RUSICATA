import subprocess
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from . import telemetry
from .models import Service, HttpRule, TransportLevelRule

def index(request):
    return render(request, 'rusicata_manager/index.html')

@login_required
def dashboard(request):
    # Check if Suricata is running
    try:
        subprocess.run(['pidof', 'suricata'], check=True, stdout=subprocess.DEVNULL)
        status = 'Active'
    except (subprocess.CalledProcessError, FileNotFoundError):
        status = 'Inactive'

    stats = telemetry.get_stats()
    recent_events = telemetry.get_recent_events(n=20)
    services = Service.objects.all()

    context = {
        'status': status,
        'stats': stats,
        'recent_events': recent_events,
        'services': services,
    }
    return render(request, 'rusicata_manager/dashboard.html', context)

@login_required
def service_rules(request, service_id):
    service = get_object_or_404(Service, id=service_id)
    http_rules = service.httprule_set.all()
    transport_rules = service.transportlevelrule_set.all()
    return render(request, 'rusicata_manager/service_rules.html', {
        'service': service,
        'http_rules': http_rules,
        'transport_rules': transport_rules,
    })

@login_required
def toggle_rule(request, rule_type, rule_id):
    if rule_type == 'http':
        rule = get_object_or_404(HttpRule, id=rule_id)
    else:
        rule = get_object_or_404(TransportLevelRule, id=rule_id)
    
    rule.is_active = not rule.is_active
    rule.save()
    return redirect('service_rules', service_id=rule.service.id)

@login_required
def toggle_all_rules(request, service_id, action):
    service = get_object_or_404(Service, id=service_id)
    active = (action == 'enable')
    # Use individual save to trigger physical rule update and hot-reload
    for rule in service.httprule_set.all():
        if rule.is_active != active:
            rule.is_active = active
            rule.save()
    for rule in service.transportlevelrule_set.all():
        if rule.is_active != active:
            rule.is_active = active
            rule.save()
    return redirect('service_rules', service_id=service_id)
