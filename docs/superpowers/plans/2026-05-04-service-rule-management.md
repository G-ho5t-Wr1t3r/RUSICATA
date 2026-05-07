# Service Rule Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide a UI to enable/disable Suricata rules for each service individually or collectively.

**Architecture:** Add Django views for rule management, update URLs, and create/modify templates to show services and their rules.

**Tech Stack:** Django, Vanilla CSS, SQLite (via Django ORM), Suricata (backend interaction).

---

### Task 1: Update Dashboard to list Services

**Files:**
- Modify: `rusicata_manager/templates/rusicata_manager/dashboard.html`
- Modify: `rusicata_manager/views.py`

- [ ] **Step 1: Update dashboard view to include services**

```python
# In rusicata_manager/views.py
from .models import Service # Ensure Service is imported

@login_required
def dashboard(request):
    # ... existing code ...
    services = Service.objects.all()
    # ...
    context = {
        'status': status,
        'stats': stats,
        'recent_events': recent_events,
        'services': services, # Add services to context
    }
    return render(request, 'rusicata_manager/dashboard.html', context)
```

- [ ] **Step 2: Add Services card to dashboard.html**

```html
<!-- In rusicata_manager/templates/rusicata_manager/dashboard.html -->
<!-- Add this card above Recent Alerts -->
<div class="card" style="margin-bottom: 20px;">
    <h2>Managed Services</h2>
    <div style="overflow-x: auto;">
        <table>
            <thead>
                <tr>
                    <th>Service Name</th>
                    <th>Port</th>
                    <th>HTTP Rules</th>
                    <th>Transport Rules</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for service in services %}
                <tr>
                    <td>{{ service.name }}</td>
                    <td>{{ service.port }}</td>
                    <td>{{ service.httprule_set.count }}</td>
                    <td>{{ service.transportlevelrule_set.count }}</td>
                    <td>
                        <a href="{% url 'service_rules' service.id %}" style="color: var(--primary-color); text-decoration: none; font-weight: bold;">Manage Rules</a>
                    </td>
                </tr>
                {% empty %}
                <tr>
                    <td colspan="5" style="text-align: center;">No services defined.</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
```

- [ ] **Step 3: Commit**

```bash
git add rusicata_manager/views.py rusicata_manager/templates/rusicata_manager/dashboard.html
git commit -m "feat: add services list to dashboard"
```

### Task 2: Implement Service Rules View

**Files:**
- Create: `rusicata_manager/templates/rusicata_manager/service_rules.html`
- Modify: `rusicata_manager/views.py`
- Modify: `rusicata_manager/urls.py`

- [ ] **Step 1: Add URLs for service rules**

```python
# In rusicata_manager/urls.py
path("service/<int:service_id>/rules/", views.service_rules, name="service_rules"),
path("rule/toggle/<str:rule_type>/<int:rule_id>/", views.toggle_rule, name="toggle_rule"),
path("service/<int:service_id>/toggle-all/<str:action>/", views.toggle_all_rules, name="toggle_all_rules"),
```

- [ ] **Step 2: Implement views in views.py**

```python
# In rusicata_manager/views.py
from django.shortcuts import get_object_or_404, redirect
from .models import Service, HttpRule, TransportLevelRule

@login_required
def service_rules(request, service_id):
    service = get_object_or_404(Service, pk=service_id)
    http_rules = HttpRule.objects.filter(service=service)
    transport_rules = TransportLevelRule.objects.filter(service=service)
    return render(request, 'rusicata_manager/service_rules.html', {
        'service': service,
        'http_rules': http_rules,
        'transport_rules': transport_rules,
    })

@login_required
def toggle_rule(request, rule_type, rule_id):
    if rule_type == 'http':
        rule = get_object_or_404(HttpRule, pk=rule_id)
    else:
        rule = get_object_or_404(TransportLevelRule, pk=rule_id)
    
    rule.is_active = not rule.is_active
    rule.save()
    return redirect('service_rules', service_id=rule.service.id)

@login_required
def toggle_all_rules(request, service_id, action):
    service = get_object_or_404(Service, pk=service_id)
    is_active = (action == 'enable')
    
    for rule in HttpRule.objects.filter(service=service):
        rule.is_active = is_active
        rule.save()
        
    for rule in TransportLevelRule.objects.filter(service=service):
        rule.is_active = is_active
        rule.save()
        
    return redirect('service_rules', service_id=service.id)
```

- [ ] **Step 3: Create service_rules.html template**

```html
<!-- rusicata_manager/templates/rusicata_manager/service_rules.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ service.name }} Rules - Rusicata</title>
    <style>
        /* Reuse styles from dashboard.html or link a common CSS */
        :root {
            --bg-color: #f4f7f6;
            --card-bg: #ffffff;
            --text-color: #333;
            --primary-color: #2c3e50;
            --success-color: #27ae60;
            --danger-color: #c0392b;
            --border-color: #ddd;
        }
        body { font-family: sans-serif; background: var(--bg-color); color: var(--text-color); padding: 20px; }
        .card { background: var(--card-bg); border-radius: 8px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; border-bottom: 1px solid var(--border-color); text-align: left; }
        .btn { padding: 5px 10px; border-radius: 4px; text-decoration: none; color: white; font-weight: bold; }
        .btn-toggle { background: var(--primary-color); }
        .btn-enable { background: var(--success-color); }
        .btn-disable { background: var(--danger-color); }
        .status-active { color: var(--success-color); font-weight: bold; }
        .status-inactive { color: var(--danger-color); font-weight: bold; }
    </style>
</head>
<body>
    <header style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h1>Rules for {{ service.name }} (Port: {{ service.port }})</h1>
        <a href="{% url 'dashboard' %}" style="text-decoration: none; color: var(--primary-color);">&larr; Back to Dashboard</a>
    </header>

    <div class="card">
        <div style="margin-bottom: 20px;">
            <a href="{% url 'toggle_all_rules' service.id 'enable' %}" class="btn btn-enable">Enable All Rules</a>
            <a href="{% url 'toggle_all_rules' service.id 'disable' %}" class="btn btn-disable">Disable All Rules</a>
        </div>

        <h3>HTTP Rules</h3>
        <table>
            <thead>
                <tr>
                    <th>SID</th>
                    <th>Action</th>
                    <th>Method</th>
                    <th>Content</th>
                    <th>Status</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {% for rule in http_rules %}
                <tr>
                    <td>{{ rule.sid }}</td>
                    <td>{{ rule.action }}</td>
                    <td>{{ rule.request_method }}</td>
                    <td>{{ rule.content }}</td>
                    <td>
                        <span class="{% if rule.is_active %}status-active{% else %}status-inactive{% endif %}">
                            {{ rule.is_active|yesno:"Active,Inactive" }}
                        </span>
                    </td>
                    <td>
                        <a href="{% url 'toggle_rule' 'http' rule.id %}" class="btn btn-toggle">Toggle</a>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h3 style="margin-top: 30px;">Transport Rules</h3>
        <table>
            <thead>
                <tr>
                    <th>SID</th>
                    <th>Action</th>
                    <th>Protocol</th>
                    <th>Direction</th>
                    <th>Content</th>
                    <th>Status</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {% for rule in transport_rules %}
                <tr>
                    <td>{{ rule.sid }}</td>
                    <td>{{ rule.action }}</td>
                    <td>{{ rule.protocol }}</td>
                    <td>{{ rule.flow_direction }}</td>
                    <td>{{ rule.content }}</td>
                    <td>
                        <span class="{% if rule.is_active %}status-active{% else %}status-inactive{% endif %}">
                            {{ rule.is_active|yesno:"Active,Inactive" }}
                        </span>
                    </td>
                    <td>
                        <a href="{% url 'toggle_rule' 'transport' rule.id %}" class="btn btn-toggle">Toggle</a>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
```

- [ ] **Step 4: Commit**

```bash
git add rusicata_manager/views.py rusicata_manager/urls.py rusicata_manager/templates/rusicata_manager/service_rules.html
git commit -m "feat: implement service rules management UI"
```

### Task 3: Verification

**Files:**
- N/A

- [ ] **Step 1: Verify rule toggling**
    - Click "Toggle" on a rule.
    - Check if it changes status in UI.
    - Check if Suricata `.rules` file is updated (disabled rule should be removed).
- [ ] **Step 2: Verify Toggle All**
    - Click "Enable All" and "Disable All".
    - Check if all rules update correctly.
