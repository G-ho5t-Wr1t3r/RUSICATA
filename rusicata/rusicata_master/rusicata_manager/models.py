from django.db import models
from django.core.validators import MaxValueValidator
from django.core.validators import MinValueValidator
import os
import os
import json
from django.db.models.signals import pre_delete

from django.dispatch import receiver
import re
import yaml
import subprocess

RULES_BASE_PATH = '/var/lib/suricata/rules/'
CONFIG_BASE_PATH = '/etc/suricata/'
SURICATA_YAML_HEADER = '%YAML 1.1\n---\n'

import threading

# ==========================================================================================================================
# SURICATA INTERACTION CORE FUNCTIONS 

def suricata_hot_reload():
    # Attempt hot reload using SIGUSR2. Priority to original command style.
    try:
        # Original style: try pidof first
        subprocess.run('kill -USR2 $(pidof suricata)', shell=True, check=True)
    except Exception:
        try:
            # Fallback to pgrep if pidof fails or is missing
            subprocess.run('kill -USR2 $(pgrep -x suricata)', shell=True, check=True)
        except Exception:
            # Last resort: pkill
            try:
                subprocess.run(['pkill', '-USR2', '-x', 'suricata'], check=True)
            except Exception:
                pass

def suricata_deamon_reload():
    # Asynchronous restart to avoid blocking the main thread (responsive frontend)
    thread = threading.Thread(target=lambda: subprocess.run(['systemctl', 'restart', 'suricata.service'], check=False))
    thread.start()

def load_suricata_config(name: str):
    file_path = f'{CONFIG_BASE_PATH}/{name}'
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)

def dump_suricata_config(data, name: str):
    file_path = f'{CONFIG_BASE_PATH}/{name}'
    with open(file_path, 'w') as f:
        f.write(SURICATA_YAML_HEADER)
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

# Generic rulify that handles both HttpRule and TransportLevelRule
def rulify(rule_instance) -> str:
    message = rule_instance.message or ""
    content = rule_instance.content or ""
    
    content_part = ""
    if content:
        nocase = "" if rule_instance.case_sensitive else "nocase;"
        location = ""
        if hasattr(rule_instance, 'content_location'):
             location = f"{rule_instance.content_location};"
        content_part = f' content:"{content}";{location}{nocase}'

    if hasattr(rule_instance, 'request_method'): # It's an HttpRule
        return f'{rule_instance.action} {rule_instance.protocol} any any -> any {rule_instance.service.port} (msg:"{message}";flow:to_server,established; content:"{rule_instance.request_method}";http_method;{content_part}sid:{rule_instance.sid};rev:1;)\n'
    else: # It's a TransportLevelRule
        flow = f'flow:{rule_instance.flow_direction},established;' if rule_instance.flow_direction != 'any' else ''
        return f'{rule_instance.action} {rule_instance.protocol} any any -> any {rule_instance.service.port} (msg:"{message}";{flow}{content_part}sid:{rule_instance.sid};rev:1;)\n'

def remove_rule(http_rule_instance):
    '''
    param: http_rule_instance (see HttpRule model)
    '''
    file_path = f'{RULES_BASE_PATH}{http_rule_instance.service.name}.rules'
    if not os.path.exists(file_path):
        return
        
    # Read file and filter lines
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Match exact sid to avoid partial matches
    pattern = f'sid:{http_rule_instance.sid};'
    filtered_lines = [line for line in lines if pattern not in line]
    
    # Write filtered lines back to the file
    with open(file_path, 'w') as file:
        file.writelines(filtered_lines)
    suricata_hot_reload()

def insert_rule(http_rule_instance):
    if hasattr(http_rule_instance, "is_active") and not http_rule_instance.is_active:
        return

    file_path = f"{RULES_BASE_PATH}{http_rule_instance.service.name}.rules"
    # Check if the file exists
    if not os.path.exists(file_path):
        with open(file_path, "w") as file:
            file.write("")

    with open(file_path, "a") as f:
        f.write(rulify(http_rule_instance))
    suricata_hot_reload()


# ==========================================================================================================================

def rewrite_service_rules(service):
    file_path = f"{RULES_BASE_PATH}{service.name}.rules"
    # Ensure directory exists
    if not os.path.exists(RULES_BASE_PATH):
        os.makedirs(RULES_BASE_PATH, exist_ok=True)
        
    with open(file_path, "w") as f:
        # We need to import HttpRule and TransportLevelRule here or move this function after them
        # to avoid circular or missing reference if called inside Service.save
        # Actually, we can use the manager
        for rule in service.httprule_set.all():
            if rule.is_active:
                f.write(rulify(rule))
        for rule in service.transportlevelrule_set.all():
            if rule.is_active:
                f.write(rulify(rule))
    suricata_hot_reload()

# Define the path for the service colors JSON file
SERVICE_COLORS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "service_colors.json")

def get_default_color(service_id):
    palette = [
        "#7c3aed", "#ef4444", "#10b981", "#3b82f6", "#f59e0b",
        "#ec4899", "#06b6d4", "#8b5cf6", "#f97316", "#14b8a6"
    ]
    return palette[service_id % len(palette)]

def sync_service_colors():
    colors = {}
    try:
        from .models import Service
        for service in Service.objects.all():
            colors[str(service.id)] = service.color
        with open(SERVICE_COLORS_FILE, "w") as f:
            json.dump(colors, f, indent=4)
    except Exception:
        pass

# A service has a port, a name and a list of rules associated
class Service(models.Model):
    name = models.CharField(max_length=200, unique=True, help_text="Nome del Service")
    port = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(65535)],
        help_text="Porta su cui runna (non interna di docker)",
    )
    color = models.CharField(max_length=7, blank=True, help_text="Hex color code (e.g. #7c3aed)")

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        is_new = not self.pk
        
        # Assign default color if not provided
        if not self.color:
            if is_new:
                self.color = get_default_color(Service.objects.count())
            else:
                self.color = get_default_color(self.id)

        if is_new:
            # Create a rule file
            file_path = RULES_BASE_PATH + self.name + ".rules"
            if not os.path.exists(file_path):
                with open(file_path, "w") as f:
                    f.write("")

            # Load it inside yaml
            loaded_config = load_suricata_config("suricata.yaml")
            if self.name + ".rules" not in loaded_config["rule-files"]:
                loaded_config["rule-files"].append(self.name + ".rules")

            # Dump updated suricata.yaml BEFORE reload
            dump_suricata_config(loaded_config, "suricata.yaml")
        else:
            # Check for name or port change
            old_service = Service.objects.get(pk=self.pk)
            name_changed = old_service.name != self.name
            port_changed = old_service.port != self.port
            
            if name_changed:
                # Rename rules file
                old_path = RULES_BASE_PATH + old_service.name + ".rules"
                new_path = RULES_BASE_PATH + self.name + ".rules"
                if os.path.exists(old_path):
                    os.rename(old_path, new_path)
                
                # Update yaml
                try:
                    loaded_config = load_suricata_config("suricata.yaml")
                    old_rule_file = old_service.name + ".rules"
                    new_rule_file = self.name + ".rules"
                    if old_rule_file in loaded_config["rule-files"]:
                        idx = loaded_config["rule-files"].index(old_rule_file)
                        loaded_config["rule-files"][idx] = new_rule_file
                        dump_suricata_config(loaded_config, "suricata.yaml")
                        suricata_deamon_reload()
                except Exception:
                    pass

        super().save(*args, **kwargs)
        
        # Sync to JSON after save
        sync_service_colors()
        
        if is_new:
            # Restart suricata to load new config (after DB commit)
            suricata_deamon_reload()
        else:
            # Check if we need to rewrite rules due to port change
            rewrite_service_rules(self)

    def delete(self, *args, **kwargs):
        # Remove from yaml
        try:
            loaded_config = load_suricata_config("suricata.yaml")
            rule_file = self.name + ".rules"
            if rule_file in loaded_config["rule-files"]:
                loaded_config["rule-files"].remove(rule_file)
            dump_suricata_config(loaded_config, "suricata.yaml")
        except Exception:
            pass
        
        # Delete rules file
        file_path = RULES_BASE_PATH + self.name + ".rules"
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass
            
        super().delete(*args, **kwargs)
        sync_service_colors()
        suricata_deamon_reload()


# alert http any any -> any 8000 (msg:"HTTP request for pruppetta on port 8000"; flow:to_server,established; content:"GET"; http_method; content:"pruppetta"; http_uri; sid:1000001; rev:1;)
# alert http any any -> any 8000 (msg:"HTTP request for pruppetta on port 8000"; flow:to_server,established; content:"GET"; http_method; content:"pruppetta"; http_uri; nocase; sid:1000001; rev:1;)
# alert http any any -> any 8000 (msg:"HTTP request for pruppetta on port 8000"; flow:to_server,established; content:"GET"; http_method; pcre:"/(pruppetta)/i"; http_uri; sid:1000001; rev:1;)
# alert http any any -> any 8000 (msg:"HTTP POST request containing pruppetta in body on port 8000"; flow:to_server,established; content:"POST"; http_method; content:"pruppetta"; http_client_body; pcre:"/(pruppetta)/i"; sid:1000002; rev:1;)
# alert http any any -> any 8000 (msg:"HTTP request for pruppetta in headers on port 8000"; flow:to_server,established; content:"GET"; http_method; content:"pruppetta"; http_header; pcre:"/(pruppetta)/i"; sid:1000002; rev:1;)

class HttpRule(models.Model):
    ACTIONS = {"alert": "alert", "drop": "drop", "reject": "reject"}
    REQUEST_METHODS = {
        "GET": "GET",
        "POST": "POST",
        "PUT": "PUT",
        "PATCH": "PATCH",
        "DELETE": "DELETE",
    }
    LOCATIONS = {
        "http_uri": "http_uri",
        "http_client_body": "http_client_body",
        "http_header": "http_header",
    }
    service = models.ForeignKey(
        Service,
        on_delete=models.CASCADE,
        help_text="Servizio sul quale applicare la regola.",
    )
    sid = models.IntegerField()
    protocol = models.CharField(
        max_length=10, choices={"http": "http"}, help_text="Protocollo sul quale agire."
    )
    action = models.CharField(
        max_length=10, choices=ACTIONS, help_text="Azione da eseguire."
    )
    message = models.CharField(
        max_length=1000, 
        help_text="Messaggio (qualsiasi).", 
        null=True, 
        blank=True
    )
    request_method = models.CharField(
        max_length=10, choices=REQUEST_METHODS, help_text="Metodo sul quale agire."
    )
    content = models.CharField(
        max_length=1000, 
        help_text="Contenuto da bloccare ('TRIGGER')",
        null=True,
        blank=True
    )
    case_sensitive = models.BooleanField(default=False)
    content_location = models.CharField(
        max_length=20, 
        choices=LOCATIONS, 
        help_text="Dove si trova il content"
    )
    is_active = models.BooleanField(
        default=True, help_text="Indica se la regola è attiva in Suricata"
    )

    def save(self, *args, **kwargs):
        if self.pk:  
            remove_rule(self)
        else:
            service_id = self.service.id
            max_http = HttpRule.objects.filter(service=self.service).aggregate(models.Max('sid'))['sid__max'] or 0
            max_transport = TransportLevelRule.objects.filter(service=self.service).aggregate(models.Max('sid'))['sid__max'] or 0
            current_max = max(max_http, max_transport)
            if current_max == 0:
                self.sid = (service_id * 100000) + 1
            else:
                self.sid = current_max + 1
        
        super().save(*args, **kwargs)
        insert_rule(self)

    def delete(self, *args, **kwargs):
        remove_rule(self)
        super().delete(*args, **kwargs)

    def __str__(self):
        return f"{self.service.name}: {self.action} : {self.request_method} : {self.content_location} : {self.content}"


@receiver(pre_delete, sender=HttpRule)
def pre_delete_callback(sender, instance, using, **kwargs):
    """
    This is a signal receiver integrated in Django.
    """
    print(f"Deleting instance with id {instance.sid}")
    try:
        remove_rule(instance)
    except Exception:
        pass


class TransportLevelRule(models.Model):
    ACTIONS = {"alert": "alert", "drop": "drop", "reject": "reject"}

    # Supported transport protocols
    PROTOCOLS = {"tcp": "tcp", "udp": "udp"}

    # Transport flow directions
    FLOW_DIRECTIONS = {"to_server": "to_server", "to_client": "to_client", "any": "any"}

    service = models.ForeignKey(
        "Service", on_delete=models.CASCADE, help_text="Service to apply rule."
    )
    sid = models.IntegerField()
    protocol = models.CharField(
        max_length=10, choices=PROTOCOLS, help_text="Transport protocol to evaluate."
    )
    action = models.CharField(
        max_length=10, choices=ACTIONS, help_text="Action to execute."
    )
    message = models.CharField(
        max_length=1000, 
        help_text="Rule alert message.",
        null=True,
        blank=True
    )
    content = models.CharField(
        max_length=1000, 
        help_text="Trigger payload content.",
        null=True,
        blank=True
    )
    case_sensitive = models.BooleanField(default=False)
    flow_direction = models.CharField(
        max_length=20,
        choices=FLOW_DIRECTIONS,
        default="any",
        help_text="Flow direction.",
    )
    is_active = models.BooleanField(
        default=True, help_text="Indica se la regola è attiva in Suricata"
    )

    def save(self, *args, **kwargs):
        if self.pk:
            remove_rule(self)
        else:
            # Generate SID only for new rules
            service_id = self.service.id
            max_http = HttpRule.objects.filter(service=self.service).aggregate(models.Max('sid'))['sid__max'] or 0
            max_transport = TransportLevelRule.objects.filter(service=self.service).aggregate(models.Max('sid'))['sid__max'] or 0
            current_max = max(max_http, max_transport)
            if current_max == 0:
                self.sid = (service_id * 100000) + 1
            else:
                self.sid = current_max + 1

        super().save(*args, **kwargs)
        insert_rule(self)


    def delete(self, *args, **kwargs):
        remove_rule(self)
        super().delete(*args, **kwargs)

    def __str__(self):
        return f'{self.service.name}: {self.action} : {self.protocol.upper()} : {self.flow_direction} : {self.content}'

@receiver(pre_delete, sender=TransportLevelRule)
def pre_delete_callback(sender, instance, using, **kwargs):
    print(f"Pre-delete signal: {instance.sid}")
    try:
        remove_rule(instance)
    except Exception:
        pass


class GlobalRule(models.Model):
    ACTIONS = {"alert": "alert", "drop": "drop", "reject": "reject"}
    PROTOCOLS = {"tcp": "tcp", "udp": "udp", "http": "http", "icmp": "icmp"}

    sid = models.IntegerField(unique=True)
    protocol = models.CharField(max_length=10, choices=PROTOCOLS, default="tcp")
    action = models.CharField(max_length=10, choices=ACTIONS, default="alert")
    message = models.CharField(max_length=1000)
    content = models.CharField(max_length=1000, help_text="Stringa o regex da cercare")
    is_regex = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        if not self.sid:
            max_sid = GlobalRule.objects.all().aggregate(models.Max('sid'))['sid__max'] or 2000000
            self.sid = max_sid + 1

        if self.pk:
            remove_global_rule(self)

        super().save(*args, **kwargs)
        if self.is_active:
            insert_global_rule(self)

    def delete(self, *args, **kwargs):
        remove_global_rule(self)
        super().delete(*args, **kwargs)

def rulify_global(rule):
    content_part = ""
    if rule.content:
        content_part = f'pcre:"/{rule.content}/"' if rule.is_regex else f'content:"{rule.content}"'
        content_part = f" {content_part};"
        
    return f'{rule.action} {rule.protocol} any any -> any any (msg:"{rule.message}";{content_part} sid:{rule.sid}; rev:1;)\n'

GLOBAL_RULES_FILE = f'{RULES_BASE_PATH}global.rules'

def insert_global_rule(rule):
    if not os.path.exists(GLOBAL_RULES_FILE):
        with open(GLOBAL_RULES_FILE, 'w') as f: f.write("")
        # Add to suricata.yaml if not present
        config = load_suricata_config('suricata.yaml')
        if 'global.rules' not in config['rule-files']:
            config['rule-files'].append('global.rules')
            dump_suricata_config(config, 'suricata.yaml')
            suricata_deamon_reload()

    with open(GLOBAL_RULES_FILE, 'a') as f:
        f.write(rulify_global(rule))
    suricata_hot_reload()

def remove_global_rule(rule):
    if not os.path.exists(GLOBAL_RULES_FILE): return
    with open(GLOBAL_RULES_FILE, 'r') as f:
        lines = f.readlines()
    with open(GLOBAL_RULES_FILE, 'w') as f:
        for line in lines:
            if f'sid:{rule.sid};' not in line:
                f.write(line)
    suricata_hot_reload()

    with open(GLOBAL_RULES_FILE, 'a') as f:
        f.write(rulify_global(rule))
    suricata_hot_reload()

def remove_global_rule(rule):
    if not os.path.exists(GLOBAL_RULES_FILE): return
    with open(GLOBAL_RULES_FILE, 'r') as f:
        lines = f.readlines()
    with open(GLOBAL_RULES_FILE, 'w') as f:
        for line in lines:
            if f'sid:{rule.sid};' not in line:
                f.write(line)
    suricata_hot_reload()