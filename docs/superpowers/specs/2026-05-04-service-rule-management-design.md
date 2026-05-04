# Spec: Service Rule Management UI

## 1. Overview
The goal is to provide a user interface to manage Suricata rules on a per-service basis. Users should be able to see which rules are active and toggle them individually or collectively.

## 2. UI/UX Design

### 2.1 Dashboard Update
- **Location:** `rusicata_manager/templates/rusicata_manager/dashboard.html`
- **Change:** Add a "Managed Services" card.
- **Content:** Table with columns: Service Name, Port, Rules Count, Actions.
- **Action:** Link to `/service/<id>/rules/`.

### 2.2 Service Rules Page
- **Location:** `rusicata_manager/templates/rusicata_manager/service_rules.html`
- **Structure:**
    - Header with Service Name and Port.
    - "Back to Dashboard" link.
    - Global controls: "Enable All", "Disable All".
    - Section: **HTTP Rules**
        - Table: SID, Action, Method, Content, Status, Toggle Button.
    - Section: **Transport Rules**
        - Table: SID, Action, Protocol, Direction, Content, Status, Toggle Button.

## 3. Technical Implementation

### 3.1 Views (`rusicata_manager/views.py`)
- `service_rules(request, service_id)`:
    - Get `Service` or 404.
    - Get `HttpRule` queryset.
    - Get `TransportLevelRule` queryset.
    - Context: `service`, `http_rules`, `transport_rules`.
- `toggle_rule(request, rule_type, rule_id)`:
    - Get rule by type and id.
    - `rule.is_active = not rule.is_active`.
    - `rule.save()`.
    - Redirect to `service_rules`.
- `toggle_all_rules(request, service_id, action)`:
    - Get service.
    - Action is 'enable' or 'disable'.
    - Update all rules (both types) for the service.
    - Redirect to `service_rules`.

### 3.2 URL Patterns (`rusicata_manager/urls.py`)
```python
path("service/<int:service_id>/rules/", views.service_rules, name="service_rules"),
path("rule/toggle/<str:rule_type>/<int:rule_id>/", views.toggle_rule, name="toggle_rule"),
path("service/<int:service_id>/toggle-all/<str:action>/", views.toggle_all_rules, name="toggle_all_rules"),
```

### 3.3 Models Interaction
- Calling `.save()` on `HttpRule` or `TransportLevelRule` automatically triggers `remove_rule()` and `insert_rule()` which handles Suricata hot reload.
- `insert_rule()` respects the `is_active` flag.

## 4. Verification Plan
- Manual verification of the UI.
- Verify that toggling a rule updates the `.rules` file (e.g., rule is removed if disabled, added if enabled).
- Verify Suricata hot reload is triggered.
