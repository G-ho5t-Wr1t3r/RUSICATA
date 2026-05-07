from django.db import models
from django.core.validators import MaxValueValidator
from django.core.validators import MinValueValidator
import os
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
    # Hot reload is usually fast, but we can still thread it if needed.
    # For now, let's keep it simple as it's just a signal.
    subprocess.run('kill -usr2 $(pidof suricata)',shell=True,text=True)

def _bg_reload():
    subprocess.run(['systemctl','restart','suricata.service'])

def suricata_deamon_reload():
    threading.Thread(target=_bg_reload).start()

def load_suricata_config(name: str):
    file_path = f'{CONFIG_BASE_PATH}/{name}'
    return yaml.safe_load(open(file_path, 'r'))

def dump_suricata_config(data, name: str):
    file_path = f'{CONFIG_BASE_PATH}/{name}'
    #yaml.dump(data,open(file_path,'w'))
    with open(file_path, 'w') as f:
        f.write(SURICATA_YAML_HEADER)
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

# Generic rulify that handles both HttpRule and TransportLevelRule
def rulify(rule_instance) -> str:
    if hasattr(rule_instance, 'request_method'): # It's an HttpRule
        return f'{rule_instance.action} {rule_instance.protocol} any any -> any {rule_instance.service.port} (msg:"{rule_instance.message}";flow:to_server,established; content:"{rule_instance.request_method}";http_method; content:"{rule_instance.content}";{rule_instance.content_location};{"" if rule_instance.case_sensitive else "nocase;"}sid:{rule_instance.sid};rev:1;)\n'
    else: # It's a TransportLevelRule
        flow = f'flow:{rule_instance.flow_direction},established;' if rule_instance.flow_direction != 'any' else ''
        return f'{rule_instance.action} {rule_instance.protocol} any any -> any {rule_instance.service.port} (msg:"{rule_instance.message}";{flow} content:"{rule_instance.content}";{"" if rule_instance.case_sensitive else "nocase;"}sid:{rule_instance.sid};rev:1;)\n'

def remove_rule(http_rule_instance):
    '''
    param: http_rule_instance (see HttpRule model)
    '''
    file_path = f'{RULES_BASE_PATH}{http_rule_instance.service.name}.rules'
    # Read file and filter lines
    with open(file_path, 'r') as file:
        lines = file.readlines()

    filtered_lines = [line for line in lines if f'sid:{http_rule_instance.sid};' not in line]
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
        # Create the file if it does not exist
        with open(file_path, "w") as file:
            file.write("")  # Create an empty file

    with open(file_path, "a") as f:
        f.write(rulify(http_rule_instance))
    suricata_hot_reload()


# ==========================================================================================================================

# A service has a port, a name and a list of rules associated
class Service(models.Model):
    name = models.CharField(max_length=200, help_text="Nome del Service")
    port = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(65535)],
        help_text="Porta su cui runna (non interna di docker)",
    )

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.pk:  # Check if the instance is being created (not updated)
            # Create a rule file
            file_path = RULES_BASE_PATH + self.name + ".rules"
            with open(file_path, "w") as f:
                f.write("")

            # Load it inside yaml
            loaded_config = load_suricata_config("suricata.yaml")
            loaded_config["rule-files"].append(self.name + ".rules")

            # Save indented yaml file
            with open("suricata.yaml", "w") as f:
                yaml.dump(loaded_config, f, default_flow_style=False, indent=4)

            # Restart suricata to load new config
            suricata_deamon_reload()

            # Dump updated suricata.yaml
            dump_suricata_config(loaded_config, "suricata.yaml")

        # Call the original save method to save the changes to the database
        super().save(*args, **kwargs)


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
    message = models.CharField(max_length=1000, help_text="Messaggio (qualsiasi).")
    request_method = models.CharField(
        max_length=10, choices=REQUEST_METHODS, help_text="Metodo sul quale agire."
    )
    content = models.CharField(
        max_length=1000, help_text="Contenuto da bloccare ('TRIGGER')"
    )
    case_sensitive = models.BooleanField(default=False)
    content_location = models.CharField(
        max_length=20, choices=LOCATIONS, help_text="Dove si trova il content"
    )
    is_active = models.BooleanField(
        default=True, help_text="Indica se la regola è attiva in Suricata"
    )

    def save(self, *args, **kwargs):
        if self.pk:  # Update
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
    message = models.CharField(max_length=1000, help_text="Rule alert message.")
    content = models.CharField(max_length=1000, help_text="Trigger payload content.")
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
    content_part = f'pcre:"/{rule.content}/"' if rule.is_regex else f'content:"{rule.content}"'
    return f'{rule.action} {rule.protocol} any any -> any any (msg:"{rule.message}"; {content_part}; sid:{rule.sid}; rev:1;)\n'

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