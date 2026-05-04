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

# ==========================================================================================================================
# SURICATA INTERACTION CORE FUNCTIONS 

def suricata_hot_reload():
    subprocess.run('kill -usr2 $(pidof suricata)',shell=True,text=True)

def suricata_deamon_reload():
    subprocess.run(['systemctl','restart','suricata.service'])

def load_suricata_config(name: str):
    file_path = f'{CONFIG_BASE_PATH}/{name}'
    return yaml.safe_load(open(file_path, 'r'))

def dump_suricata_config(data, name: str):
    file_path = f'{CONFIG_BASE_PATH}/{name}'
    #yaml.dump(data,open(file_path,'w'))
    with open(file_path, 'w') as f:
        f.write(SURICATA_YAML_HEADER)
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

# alert http any any -> any 8000 (msg:"HTTP request for pruppetta on port 8000"; flow:to_server,established; content:"GET"; http_method; content:"pruppetta"; http_uri; sid:1000001; rev:1;)
def rulify(http_rule_instance) -> str:
    return f'{http_rule_instance.action} {http_rule_instance.protocol} any any -> any {http_rule_instance.service.port} (msg:"{http_rule_instance.message}";flow:to_server,established; content:"{http_rule_instance.request_method}";http_method; content:"{http_rule_instance.content}";{http_rule_instance.content_location};{"" if http_rule_instance.case_sensitive else "nocase;"}sid:{http_rule_instance.sid};rev:1;)\n'

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

        service_id = self.service.id
        num_rules = HttpRule.objects.filter(service=self.service).count()
        self.sid = (service_id * 100000) + num_rules + 1
        # Call the original save method to save the changes to the database
        super().save(*args, **kwargs)

        # Call the create_file function with the current instance
        insert_rule(self)

        def delete(self, *args, **kwargs):
            # Call the original delete method to delete the instance
            remove_rule(self)
            super().delete(*args, **kwargs)

    def __str__(self):
        return f"{self.service.name}: {self.action} : {self.request_method} : {self.content_location} : {self.content}"


@receiver(pre_delete, sender=HttpRule)
def pre_delete_callback(sender, instance, using, **kwargs):
    """
    This is a signal receiver integrated in Django.
    Why? It makes possible to execute some custom logic before removing a rule.
    Clean the file system removing fisically the Suricata rule from .rules file.
    Runs automatically in a transparent way before deleting HttpRule model from the db. 
    With the @receiver(pre_delete, sender=HttpRule) decorator, Django auto-invoke for every deleting action on that model.
    """
    print(f"Deleting instance with id {instance.sid}")
    remove_rule(instance)


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
        try:
            if self.pk:
                # Update existing rule logic
                print(f"Updating transport rule: {self.pk}")
                remove_rule(self)

            # Calculate the new SID
            service_id = self.service.id
            num_rules = TransportLevelRule.objects.filter(service=self.service).count()
            self.sid = (service_id * 100000) + num_rules + 1

            # Save into database
            super().save(*args, **kwargs)

            # Insert physical rule
            print(f"Inserting transport rule: {self.sid}")
            insert_rule(self)

        except Exception as e:
            # Handle save exceptions
            print(f"Error during save: {e}")


    def delete(self, *args, **kwargs):
        try:            
            # Remove physical rule
            print(f"Deleting transport rule: {self.sid}")
            remove_rule(self)
            
            # Delete from database
            super().delete(*args, **kwargs)
            
        except Exception as e:
            # Handle delete exceptions
            print(f"Error during delete: {e}")

    def __str__(self):
        return f'{self.service.name}: {self.action} : {self.protocol.upper()} : {self.flow_direction} : {self.content}'

@receiver(pre_delete, sender=TransportLevelRule)
def pre_delete_callback(sender, instance, using, **kwargs):
    # Triggered before deleting
    print(f"Pre-delete signal: {instance.sid}")
    try:
        remove_rule(instance)
    except Exception as e:
        # Handle signal exceptions
        print(f"Error in pre_delete: {e}")