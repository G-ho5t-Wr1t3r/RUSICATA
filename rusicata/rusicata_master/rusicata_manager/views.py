from django.http import JsonResponse, HttpResponse
import subprocess
import os
import datetime
import tarfile
import io
import shutil
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User, Group
from django.contrib import messages
from functools import wraps
from . import telemetry
from .models import Service, HttpRule, TransportLevelRule, load_suricata_config

ACTIVITY_LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'activity.log')

# Suricata records the per-event verdict in eve.json at the time the event fires
# ("allowed" for alert rules, "blocked" for drop/reject rules). eve.json is
# append-only, so this verdict is immutable: past events keep what they had when
# they fired, and only new events reflect a later rule change. We map it to the
# two-state label the dashboard badges/filters already use (ALERT / DROP) instead
# of re-deriving the action from the live rule (which rewrote the whole history).
ACTION_DISPLAY = {
    'allowed': 'ALERT',
    'blocked': 'DROP',
}

def display_action(raw_action):
    if not raw_action:
        return 'ALERT'
    return ACTION_DISPLAY.get(raw_action.lower(), raw_action.upper())

def is_analyst(user):
    return user.groups.filter(name='Analyst').exists()

def superuser_only(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_superuser:
            if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.GET.get('format') == 'json':
                return JsonResponse({
                    'status': 'error', 
                    'message': 'Permission Denied: Only Superusers can perform this action.'
                }, status=403)
            return render(request, 'rusicata_manager/permission_denied.html', status=403)
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def analyst_or_superuser(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not (request.user.is_superuser or is_analyst(request.user)):
            if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.GET.get('format') == 'json':
                return JsonResponse({
                    'status': 'error', 
                    'message': 'Permission Denied.'
                }, status=403)
            return render(request, 'rusicata_manager/permission_denied.html', status=403)
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def log_activity(user, action, details):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] User {user.username}: {action} - {details}\n"
    try:
        with open(ACTIVITY_LOG_FILE, 'a') as f:
            f.write(log_entry)
    except Exception:
        pass

def get_recent_logs(n=10):
    if not os.path.exists(ACTIVITY_LOG_FILE):
        return []
    try:
        with open(ACTIVITY_LOG_FILE, 'r') as f:
            lines = f.readlines()
            return [line.strip() for line in lines[-n:][::-1]]
    except Exception:
        return []

@login_required
@superuser_only
def create_analyst(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username and password:
            if User.objects.filter(username=username).exists():
                return JsonResponse({'status': 'error', 'message': 'Username already exists'}, status=400)
            
            user = User.objects.create_user(username=username, password=password)
            group, created = Group.objects.get_or_create(name='Analyst')
            user.groups.add(group)
            log_activity(request.user, "CREATE_ANALYST", f"Created analyst user: {username}")
            return JsonResponse({'status': 'success', 'message': f'Analyst {username} created successfully'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

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
    recent_events = telemetry.get_recent_events(n=100)
    
    # Aggregations
    services = Service.objects.prefetch_related('httprule_set', 'transportlevelrule_set').all()
    events_per_service = {s.name: 0 for s in services}
    events_per_service['Other'] = 0
    
    active_rules_per_service = {}
    service_colors = {}
    
    port_to_service = {s.port: s.name for s in services}
    
    for service in services:
        active_http = service.httprule_set.filter(is_active=True).count()
        active_transport = service.transportlevelrule_set.filter(is_active=True).count()
        active_rules_per_service[service.name] = active_http + active_transport
        service_colors[service.name] = service.color

    enriched_events = []
    for i, event in enumerate(recent_events):
        dest_port = event.get('dest_port')

        service_name = port_to_service.get(dest_port, 'Other')
        if service_name in events_per_service:
            events_per_service[service_name] += 1

        if i < 20:
            event['action'] = display_action(event.get('action'))
            enriched_events.append(event)
        
    return JsonResponse({
        'status': status,
        'stats': stats,
        'system_stats': system_stats,
        'events_per_service': events_per_service,
        'active_rules_per_service': active_rules_per_service,
        'service_colors': service_colors,
        'recent_events': enriched_events,
        'is_superuser': request.user.is_superuser,
        'is_analyst': is_analyst(request.user),
        'activity_logs': get_recent_logs(15)
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
    for event in recent_events:
        event['action'] = display_action(event.get('action'))
    services = Service.objects.prefetch_related('httprule_set', 'transportlevelrule_set').all()

    for service in services:
        total_http = service.httprule_set.count()
        active_http = service.httprule_set.filter(is_active=True).count()
        total_transport = service.transportlevelrule_set.count()
        active_transport = service.transportlevelrule_set.filter(is_active=True).count()
        
        service.total_rules = total_http + total_transport
        service.active_rules = active_http + active_transport
    
    # Load recent activity logs
    activity_logs = get_recent_logs(15)

    context = {
        'status': status,
        'stats': stats,
        'recent_events': recent_events,
        'services': services,
        'is_superuser': request.user.is_superuser,
        'is_analyst': is_analyst(request.user),
        'activity_logs': activity_logs
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
        'is_superuser': request.user.is_superuser,
        'is_analyst': is_analyst(request.user)
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
        'rules': http_rules + transport_rules,
        'is_superuser': request.user.is_superuser,
        'is_analyst': is_analyst(request.user)
    })

@login_required
@superuser_only
def toggle_rule(request, rule_type, rule_id):
    if rule_type == 'http':
        rule = get_object_or_404(HttpRule, id=rule_id)
    else:
        rule = get_object_or_404(TransportLevelRule, id=rule_id)
    
    rule.is_active = not rule.is_active
    rule.save()
    
    log_activity(request.user, "TOGGLE_RULE", f"{'Enabled' if rule.is_active else 'Disabled'} {rule_type.upper()} rule SID:{rule.sid} for service {rule.service.name}")
    
    if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.GET.get('format') == 'json':
        return JsonResponse({'status': 'success', 'is_active': rule.is_active})
    
    return redirect('service_rules', service_id=rule.service.id)

@login_required
@superuser_only
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
            
    log_activity(request.user, "TOGGLE_ALL_RULES", f"{action.upper()}D all rules for service {service.name}")
    return redirect('service_rules', service_id=service_id)

@login_required
@analyst_or_superuser
def add_http_rule(request, service_id):
    if request.method == 'POST':
        action = request.POST.get('action')
        if is_analyst(request.user) and action != 'alert':
            return JsonResponse({
                'status': 'error', 
                'message': 'Permission Denied: Analyst can only create ALERT rules.'
            }, status=403)
            
        service = get_object_or_404(Service, id=service_id)
        rule = HttpRule.objects.create(
            service=service,
            protocol='http',
            action=action,
            message=request.POST.get('message'),
            request_method=request.POST.get('request_method'),
            content=request.POST.get('content'),
            content_location=request.POST.get('content_location'),
            case_sensitive=request.POST.get('case_sensitive') == 'on'
        )
        log_activity(request.user, "ADD_HTTP_RULE", f"Added HTTP rule SID:{rule.sid} to service {service.name} (Action: {action})")
        if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.GET.get('format') == 'json':
            return JsonResponse({'status': 'success'})
    return redirect('service_rules', service_id=service_id)

@login_required
@analyst_or_superuser
def add_transport_rule(request, service_id):
    if request.method == 'POST':
        action = request.POST.get('action')
        if is_analyst(request.user) and action != 'alert':
            return JsonResponse({
                'status': 'error', 
                'message': 'Permission Denied: Analyst can only create ALERT rules.'
            }, status=403)

        service = get_object_or_404(Service, id=service_id)
        rule = TransportLevelRule.objects.create(
            service=service,
            protocol=request.POST.get('protocol'),
            action=action,
            message=request.POST.get('message'),
            content=request.POST.get('content'),
            flow_direction=request.POST.get('flow_direction'),
            case_sensitive=request.POST.get('case_sensitive') == 'on'
        )
        log_activity(request.user, "ADD_TRANSPORT_RULE", f"Added {rule.protocol.upper()} rule SID:{rule.sid} to service {service.name} (Action: {action})")
        if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.GET.get('format') == 'json':
            return JsonResponse({'status': 'success'})
    return redirect('service_rules', service_id=service_id)

@login_required
@superuser_only
def delete_rule(request, rule_type, rule_id):
    if rule_type == 'http':
        rule = get_object_or_404(HttpRule, id=rule_id)
    else:
        rule = get_object_or_404(TransportLevelRule, id=rule_id)
    
    service_id = rule.service.id
    sid = rule.sid
    service_name = rule.service.name
    rule.delete()
    
    log_activity(request.user, "DELETE_RULE", f"Deleted {rule_type.upper()} rule SID:{sid} from service {service_name}")
    
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
@superuser_only
def edit_rule_api(request, rule_type, rule_id):
    if request.method == 'POST':
        if rule_type == 'http':
            rule = get_object_or_404(HttpRule, id=rule_id)
            rule.message = request.POST.get('message', rule.message)
            rule.action = request.POST.get('action', rule.action)
            # Use proto_method as request_method for HTTP rules
            rule.request_method = request.POST.get('proto_method', rule.request_method)
            rule.content = request.POST.get('content', rule.content)
            rule.content_location = request.POST.get('content_location', rule.content_location)
            rule.case_sensitive = request.POST.get('case_sensitive') == 'on'
        else:
            rule = get_object_or_404(TransportLevelRule, id=rule_id)
            rule.message = request.POST.get('message', rule.message)
            rule.action = request.POST.get('action', rule.action)
            # Use proto_method as protocol for Transport rules
            rule.protocol = request.POST.get('proto_method', rule.protocol)
            rule.content = request.POST.get('content', rule.content)
            rule.flow_direction = request.POST.get('flow_direction', rule.flow_direction)
            rule.case_sensitive = request.POST.get('case_sensitive') == 'on'
        
        rule.save()
        log_activity(request.user, "EDIT_RULE", f"Edited {rule_type.upper()} rule SID:{rule.sid} for service {rule.service.name}")
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error', 'message': 'Only POST allowed'}, status=405)

@login_required
@superuser_only
def add_service(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        port = request.POST.get('port')
        if name and port:
            # Manual check to prevent duplicates if DB unique constraint is not yet migrated
            if not Service.objects.filter(name=name).exists():
                Service.objects.create(name=name, port=port)
                log_activity(request.user, "ADD_SERVICE", f"Added service {name} on port {port}")
    return redirect('dashboard')

import re

@login_required
@superuser_only
def delete_service(request, service_id):
    service = get_object_or_404(Service, id=service_id)
    name = service.name
    service.delete()
    log_activity(request.user, "DELETE_SERVICE", f"Deleted service {name}")
    return redirect('dashboard')

@login_required
@superuser_only
def edit_service(request, service_id):
    service = get_object_or_404(Service, id=service_id)
    if request.method == 'POST':
        name = request.POST.get('name')
        port = request.POST.get('port')
        color = request.POST.get('color')
        if name and port:
            # Check for duplicate name if changed
            if name != service.name and Service.objects.filter(name=name).exists():
                return JsonResponse({'status': 'error', 'message': 'Service name already exists'}, status=400)
            
            old_name = service.name
            service.name = name
            service.port = int(port)
            if color:
                service.color = color
            service.save()
            log_activity(request.user, "EDIT_SERVICE", f"Edited service {old_name} -> {name} (Port: {port})")
            return JsonResponse({'status': 'success'})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

@login_required
def service_detail_api(request, service_id):
    service = get_object_or_404(Service, id=service_id)
    return JsonResponse({
        'id': service.id,
        'name': service.name,
        'port': service.port,
        'color': service.color
    })

@login_required
@superuser_only
def bulk_add_services(request):
    if request.method == 'POST':
        data = request.POST.get('docker_ps_output')
        if data:
            lines = data.strip().split('\n')
            # Skip header if present
            if lines and 'CONTAINER ID' in lines[0]:
                lines = lines[1:]
            
            count = 0
            for line in lines:
                parts = line.split()
                if len(parts) < 2: continue
                
                # In standard docker ps, the name is the last column
                # This might fail for some custom formats but works for default output
                name = parts[-1]
                
                # Look for ->PORT/tcp or ->PORT/udp
                port_matches = re.findall(r'->(\d+)/(?:tcp|udp)', line)
                if not port_matches:
                    # Also try standard 0.0.0.0:HOST_PORT->CONT_PORT
                    port_matches = re.findall(r'->(\d+)', line)
                
                if port_matches:
                    try:
                        port = int(port_matches[0])
                        if not Service.objects.filter(name=name).exists():
                            Service.objects.create(name=name, port=port)
                            count += 1
                    except (ValueError, IndexError):
                        continue
            
            if count > 0:
                log_activity(request.user, "BULK_ADD_SERVICES", f"Added {count} services from Docker output")
                        
    return redirect('dashboard')

@login_required
@superuser_only
def export_backup(request):
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"rusicata_snapshot_{timestamp}.tar.gz"
    
    # Create an in-memory tarball
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
        # 1. Database
        # Base dir is rusicata_master/
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_path = os.path.join(base_dir, 'db.sqlite3')
        if os.path.exists(db_path):
            tar.add(db_path, arcname='db.sqlite3')
        
        # 2. Suricata Config
        if os.path.exists('/etc/suricata/suricata.yaml'):
            tar.add('/etc/suricata/suricata.yaml', arcname='suricata.yaml')
            
        # 3. Rules
        rules_dir = '/var/lib/suricata/rules/'
        if os.path.exists(rules_dir):
            for f in os.listdir(rules_dir):
                if f.endswith('.rules'):
                    tar.add(os.path.join(rules_dir, f), arcname=f'rules/{f}')
        
        # 4. Activity Log
        if os.path.exists(ACTIVITY_LOG_FILE):
            tar.add(ACTIVITY_LOG_FILE, arcname='activity.log')

    buffer.seek(0)
    response = HttpResponse(buffer.read(), content_type='application/x-gzip')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    log_activity(request.user, "EXPORT_BACKUP", f"System snapshot exported: {filename}")
    return response

@login_required
@superuser_only
def import_backup(request):
    if request.method == 'POST' and request.FILES.get('backup_file'):
        backup_file = request.FILES['backup_file']
        try:
            with tarfile.open(fileobj=backup_file, mode='r:gz') as tar:
                # Validate contents
                names = tar.getnames()
                if 'db.sqlite3' not in names:
                    return JsonResponse({'status': 'error', 'message': 'Invalid backup: db.sqlite3 not found'}, status=400)
                
                # Extract to a temp dir
                temp_dir = '/tmp/rusicata_import'
                if os.path.exists(temp_dir): 
                    shutil.rmtree(temp_dir)
                os.makedirs(temp_dir)
                tar.extractall(temp_dir)
                
                # Restore Database
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                db_path = os.path.join(base_dir, 'db.sqlite3')
                shutil.copy2(os.path.join(temp_dir, 'db.sqlite3'), db_path)
                
                # Restore Config
                if 'suricata.yaml' in names:
                    try:
                        shutil.copy2(os.path.join(temp_dir, 'suricata.yaml'), '/etc/suricata/suricata.yaml')
                    except Exception as e:
                        pass
                
                # Restore Rules
                rules_dir = '/var/lib/suricata/rules/'
                import_rules_dir = os.path.join(temp_dir, 'rules')
                if os.path.exists(import_rules_dir):
                    for f in os.listdir(import_rules_dir):
                        shutil.copy2(os.path.join(import_rules_dir, f), os.path.join(rules_dir, f))
                
                # Restore Activity Log
                if 'activity.log' in names:
                    shutil.copy2(os.path.join(temp_dir, 'activity.log'), ACTIVITY_LOG_FILE)
                
                # Clean up
                shutil.rmtree(temp_dir)
                
                log_activity(request.user, "IMPORT_BACKUP", "System restored from snapshot")
                
                # Restart Suricata
                subprocess.run(['systemctl', 'restart', 'suricata'], check=False)
                
                return JsonResponse({'status': 'success', 'message': 'Backup restored successfully. Suricata restarted.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': f'Import failed: {str(e)}'}, status=500)
            
    return JsonResponse({'status': 'error', 'message': 'No backup file provided'}, status=400)
