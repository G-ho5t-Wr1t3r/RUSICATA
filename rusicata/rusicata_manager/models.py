from django.db import models
from django.core.validators import MaxValueValidator
from django.core.validators import MinValueValidator
import os
from django.db.models.signals import pre_delete
from django.dispatch import receiver
import re
BASE_PATH = '/tmp/'



def suricata_hot_reload():
    pass

# alert http any any -> any 8000 (msg:"HTTP request for pruppetta on port 8000"; flow:to_server,established; content:"GET"; http_method; content:"pruppetta"; http_uri; sid:1000001; rev:1;)
def rulify(http_rule_instance) -> str:
    return f'{http_rule_instance.action} {http_rule_instance.protocol} any any -> any {http_rule_instance.service.port} (msg:"{http_rule_instance.message}";flow:to_server,established; content:"{http_rule_instance.request_method}";http_method; content:"{http_rule_instance.content}";{http_rule_instance.content_location};{"" if http_rule_instance.case_sensitive else "nocase;"}sid:{http_rule_instance.sid};rev:1;)\n'

def remove_rule(http_rule_instance):
    file_path = f'{BASE_PATH}{http_rule_instance.service.name}.rules'
    # Read file and filter lines
    with open(file_path, 'r') as file:
        lines = file.readlines()

    filtered_lines = [line for line in lines if f'sid:{http_rule_instance.sid};' not in line]
    print(filtered_lines)    
    # Write filtered lines back to the file
    with open(file_path, 'w') as file:
        file.writelines(filtered_lines)
    suricata_hot_reload()

def insert_rule(http_rule_instance):
    file_path = f'{BASE_PATH}{http_rule_instance.service.name}.rules'
    # Check if the file exists
    if not os.path.exists(file_path):
        # Create the file if it does not exist
        with open(file_path, 'w') as file:
            file.write('')  # Create an empty file

    with open(file_path, 'a') as f:
        f.write(rulify(http_rule_instance))
    suricata_hot_reload()


#A service has a port, a name and a list of rules associated
class Service(models.Model):
    name = models.CharField(max_length=200)
    port = models.IntegerField(validators=[MinValueValidator(1),MaxValueValidator(65535)])

    def __str__(self):
        return self.name
    


#A rule has ???
# alert http any any -> any 8000 (msg:"HTTP request for pruppetta on port 8000"; flow:to_server,established; content:"GET"; http_method; content:"pruppetta"; http_uri; sid:1000001; rev:1;)
# alert http any any -> any 8000 (msg:"HTTP request for pruppetta on port 8000"; flow:to_server,established; content:"GET"; http_method; content:"pruppetta"; http_uri; nocase; sid:1000001; rev:1;)
# alert http any any -> any 8000 (msg:"HTTP request for pruppetta on port 8000"; flow:to_server,established; content:"GET"; http_method; pcre:"/(pruppetta)/i"; http_uri; sid:1000001; rev:1;)
# alert http any any -> any 8000 (msg:"HTTP POST request containing pruppetta in body on port 8000"; flow:to_server,established; content:"POST"; http_method; content:"pruppetta"; http_client_body; pcre:"/(pruppetta)/i"; sid:1000002; rev:1;)
# alert http any any -> any 8000 (msg:"HTTP request for pruppetta in headers on port 8000"; flow:to_server,established; content:"GET"; http_method; content:"pruppetta"; http_header; pcre:"/(pruppetta)/i"; sid:1000002; rev:1;)

class HttpRule(models.Model):
    ACTIONS = {
        "alert": "alert",
        "drop": "drop",
        "reject": "reject"
    }
    REQUEST_METHODS = {
        "GET":"GET",
        "POST":"POST",
        "PUT":"PUT",
        "PATCH":"PATCH",
        "DELETE":"DELETE",
    }
    LOCATIONS = {
        "http_uri":"http_uri",
        "http_client_body":"http_client_body",
        "http_header":"http_header"
    }
    service =  models.ForeignKey(Service, on_delete=models.CASCADE)
    sid = models.IntegerField()
    protocol = models.CharField(max_length=10,choices={'http':'http'})
    action = models.CharField(max_length=10, choices=ACTIONS)
    message = models.CharField(max_length=1000)
    request_method = models.CharField(max_length=10, choices=REQUEST_METHODS)
    content = models.CharField(max_length=1000)
    case_sensitive = models.BooleanField(default=False)
    content_location = models.CharField(max_length=20,choices=LOCATIONS)

    def save(self, *args, **kwargs):
        if self.pk: #Update
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
        return f'{self.service.name}: {self.action} : {self.request_method} : {self.content_location} : {self.content}'





@receiver(pre_delete, sender=HttpRule)
def pre_delete_callback(sender, instance, using, **kwargs):
    # Custom logic before deletion
    print(f"Deleting instance with id {instance.sid}")
    remove_rule(instance)
"""
    # Optionally perform additional actions here
    instance.remove_rules()  # Call the remove_rules method if it exists in your model

    # Note: No additional positional arguments should be defined in the handler func"""


