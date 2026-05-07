from django.http import JsonResponse
import subprocess
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from . import telemetry
from .models import Service, HttpRule, TransportLevelRule, load_suricata_config

def index(request):
    return render(request, 'rusicata_manager/index.html')

@login_required
def dashboard_stats(request):
    # Check if Suricata is running - try systemctl first, then pgrep
    status = 'Inactive'
    try:
        # Check with systemctl if available
        res = subprocess.run(['systemctl', 'is-active', 'suricata'], capture_output=True, text=True)
        if res.stdout.strip() == 'active':
            status = 'Active'
        else:
            # Fallback to pgrep
            subprocess.run(['pgrep', '-x', 'suricata'], check=True, stdout=subprocess.DEVNULL)
            status = 'Active'
    except Exception:
        # Final fallback check with pgrep via shell
        try:
            subprocess.run('pgrep -x suricata', shell=True, check=True, stdout=subprocess.DEVNULL)
            status = 'Active'
        except Exception:
            status = 'Inactive'

    stats = telemetry.get_stats()
    system_stats = telemetry.get_system_stats()
    recent_events = telemetry.get_recent_events(n=100) # Read more for better stats
    
    # Events per service aggregation
    services = Service.objects.all()
    events_per_service = {s.name: 0 for s in services}
    events_per_service['Other'] = 0
    
    port_to_service = {s.port: s.name for s in services}
    
    # Enrich recent events with exact rule actions from DB
    enriched_events = []
    for i, event in enumerate(recent_events):
        sid = event.get('sid')
        dest_port = event.get('dest_port')
        action = event.get('action')
        
        # Aggregate for chart using all 100 events
        service_name = port_to_service.get(dest_port, 'Other')
        if service_name in events_per_service:
            events_per_service[service_name] += 1
            
        if i < 20: # Only enrich and send back last 20 for UI table
            if sid:
                rule = HttpRule.objects.filter(sid=sid).first() or \
                       TransportLevelRule.objects.filter(sid=sid).first()
                if rule:
                    action = rule.action.upper()
            
            event['action'] = action
            enriched_events.append(event)
        
    # Also count using the telemetry stats (which might be more than 100 lines)
    # But for simplicity and real-time feel, we use the recent_events buffer.
    
    return JsonResponse({
        'status': status,
        'stats': stats,
        'system_stats': system_stats,
        'events_per_service': events_per_service,
        'recent_events': enriched_events,
    })

@login_required
def dashboard(request):
    # Check if Suricata is running
    try:
        subprocess.run(['pgrep', '-x', 'suricata'], check=True, stdout=subprocess.DEVNULL)
        status = 'Active'
    except (subprocess.CalledProcessError, FileNotFoundError):
        status = 'Inactive'

    stats = telemetry.get_stats()
    recent_events = telemetry.get_recent_events(n=20)
    services = Service.objects.prefetch_related('httprule_set', 'transportlevelrule_set').all()
    
    for service in services:
        total_http = service.httprule_set.count()
        active_http = service.httprule_set.filter(is_active=True).count()
        total_transport = service.transportlevelrule_set.count()
        active_transport = service.transportlevelrule_set.filter(is_active=True).count()
        
        service.total_rules = total_http + total_transport
        service.active_rules = active_http + active_transport
    
    # Load basic suricata config for display
    try:
        suricata_config = load_suricata_config('suricata.yaml')
        config_summary = {
            'rule_files': suricata_config.get('rule-files', []),
            'interfaces': [itf.get('interface') for itf in suricata_config.get('af-packet', []) if itf.get('interface')],
            'app_layer_protos': [proto for proto, cfg in suricata_config.get('app-layer', {}).get('protocols', {}).items() if cfg.get('enabled') is True]
        }
    except Exception:
        config_summary = {}

    context = {
        'status': status,
        'stats': stats,
        'recent_events': recent_events,
        'services': services,
        'config_summary': config_summary,
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
def service_rules_api(request, service_id):
    service = get_object_or_404(Service, id=service_id)
    http_rules = list(service.httprule_set.values('id', 'message', 'is_active', 'action'))
    transport_rules = list(service.transportlevelrule_set.values('id', 'message', 'is_active', 'action'))
    
    # Add type to each rule
    for r in http_rules: r['type'] = 'http'
    for r in transport_rules: r['type'] = 'transport'
    
    return JsonResponse({
        'service_name': service.name,
        'rules': http_rules + transport_rules
    })

@login_required
def toggle_rule(request, rule_type, rule_id):
    if rule_type == 'http':
        rule = get_object_or_404(HttpRule, id=rule_id)
    else:
        rule = get_object_or_404(TransportLevelRule, id=rule_id)
    
    rule.is_active = not rule.is_active
    rule.save()
    
    if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.GET.get('format') == 'json':
        return JsonResponse({'status': 'success', 'is_active': rule.is_active})
    
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

@login_required
def add_http_rule(request, service_id):
    if request.method == 'POST':
        service = get_object_or_404(Service, id=service_id)
        HttpRule.objects.create(
            service=service,
            protocol='http',
            action=request.POST.get('action'),
            message=request.POST.get('message'),
            request_method=request.POST.get('request_method'),
            content=request.POST.get('content'),
            content_location=request.POST.get('content_location'),
            case_sensitive=request.POST.get('case_sensitive') == 'on'
        )
        if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.GET.get('format') == 'json':
            return JsonResponse({'status': 'success'})
    return redirect('service_rules', service_id=service_id)

@login_required
def add_transport_rule(request, service_id):
    if request.method == 'POST':
        service = get_object_or_404(Service, id=service_id)
        TransportLevelRule.objects.create(
            service=service,
            protocol=request.POST.get('protocol'),
            action=request.POST.get('action'),
            message=request.POST.get('message'),
            content=request.POST.get('content'),
            flow_direction=request.POST.get('flow_direction'),
            case_sensitive=request.POST.get('case_sensitive') == 'on'
        )
        if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.GET.get('format') == 'json':
            return JsonResponse({'status': 'success'})
    return redirect('service_rules', service_id=service_id)

@login_required
def delete_rule(request, rule_type, rule_id):
    if rule_type == 'http':
        rule = get_object_or_404(HttpRule, id=rule_id)
    else:
        rule = get_object_or_404(TransportLevelRule, id=rule_id)
    
    service_id = rule.service.id
    rule.delete()
    
    if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.GET.get('format') == 'json':
        return JsonResponse({'status': 'success'})
    
    return redirect('service_rules', service_id=service_id)

@login_required
def rule_detail_api(request, rule_type, rule_id):
    if rule_type == 'http':
        rule = get_object_or_404(HttpRule, id=rule_id)
        data = {
            'id': rule.id,
            'message': rule.message,
            'action': rule.action,
            'protocol': rule.protocol,
            'request_method': rule.request_method,
            'content': rule.content,
            'content_location': rule.content_location,
            'case_sensitive': rule.case_sensitive,
        }
    else:
        rule = get_object_or_404(TransportLevelRule, id=rule_id)
        data = {
            'id': rule.id,
            'message': rule.message,
            'action': rule.action,
            'protocol': rule.protocol,
            'content': rule.content,
            'flow_direction': rule.flow_direction,
            'case_sensitive': rule.case_sensitive,
        }
    return JsonResponse(data)

@login_required
def edit_rule_api(request, rule_type, rule_id):
    if request.method == 'POST':
        if rule_type == 'http':
            rule = get_object_or_404(HttpRule, id=rule_id)
            rule.message = request.POST.get('message', rule.message)
            rule.action = request.POST.get('action', rule.action)
            rule.request_method = request.POST.get('request_method', rule.request_method)
            rule.content = request.POST.get('content', rule.content)
            rule.content_location = request.POST.get('content_location', rule.content_location)
            rule.case_sensitive = request.POST.get('case_sensitive') == 'on'
        else:
            rule = get_object_or_404(TransportLevelRule, id=rule_id)
            rule.message = request.POST.get('message', rule.message)
            rule.action = request.POST.get('action', rule.action)
            rule.protocol = request.POST.get('protocol', rule.protocol)
            rule.content = request.POST.get('content', rule.content)
            rule.flow_direction = request.POST.get('flow_direction', rule.flow_direction)
            rule.case_sensitive = request.POST.get('case_sensitive') == 'on'
        
        rule.save()
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error', 'message': 'Only POST allowed'}, status=405)

@login_required
def add_service(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        port = request.POST.get('port')
        if name and port:
            Service.objects.create(name=name, port=port)
    return redirect('dashboard')
