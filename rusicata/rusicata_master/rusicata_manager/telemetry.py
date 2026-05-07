import json
import os
from collections import Counter

import subprocess

DEFAULT_EVE_PATH = '/var/log/suricata/eve.json'
LOGS_DIR = '/var/log/suricata/'

def get_system_stats():
    """
    Returns RAM usage of suricata process and disk usage of logs directory.
    """
    stats = {'ram': '0 MB', 'disk': '0 MB'}
    
    # RAM usage (RSS)
    try:
        # ps -C suricata -o rss= returns RSS in KB
        output = subprocess.check_output(['ps', '-C', 'suricata', '-o', 'rss='], text=True).strip()
        if output:
            # sum in case of multiple processes
            total_kb = sum(int(line) for line in output.splitlines())
            stats['ram'] = f"{total_kb / 1024:.1f} MB"
    except (subprocess.CalledProcessError, ValueError, FileNotFoundError):
        pass

    # Disk usage of logs directory
    try:
        # du -sh returns a human readable size
        output = subprocess.check_output(['du', '-sh', LOGS_DIR], text=True).strip()
        if output:
            stats['disk'] = output.split()[0]
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
        
    return stats

def get_stats(file_path=None, max_lines=1000):
    """
    Parses Suricata's eve.json log file efficiently (low RAM usage) by reading from the end.
    Aggregates counts for actions and protocols.
    """
    if file_path is None:
        file_path = DEFAULT_EVE_PATH

    if not os.path.exists(file_path):
        return {'actions': {}, 'protocols': {}}

    actions = Counter()
    protocols = Counter()
    
    lines_read = 0
    
    with open(file_path, 'rb') as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        buffer = bytearray()
        pointer = file_size
        
        while pointer > 0 and lines_read < max_lines:
            chunk_size = min(pointer, 4096)
            pointer -= chunk_size
            f.seek(pointer)
            chunk = f.read(chunk_size)
            buffer = chunk + buffer
            
            while b'\n' in buffer and lines_read < max_lines:
                last_newline_idx = buffer.rfind(b'\n')
                line = buffer[last_newline_idx+1:].decode('utf-8', errors='ignore').strip()
                buffer = buffer[:last_newline_idx]
                
                if line:
                    try:
                        event = json.loads(line)
                        _process_event_for_stats(event, actions, protocols)
                        lines_read += 1
                    except json.JSONDecodeError:
                        pass
            
            if pointer == 0 and buffer and lines_read < max_lines:
                line = buffer.decode('utf-8', errors='ignore').strip()
                if line:
                    try:
                        event = json.loads(line)
                        _process_event_for_stats(event, actions, protocols)
                        lines_read += 1
                    except json.JSONDecodeError:
                        pass
                buffer = bytearray()

    return {
        'actions': dict(actions),
        'protocols': dict(protocols)
    }

def _process_event_for_stats(event, actions, protocols):
    action = None
    if event.get('event_type') == 'alert':
        alert = event.get('alert', {})
        action = alert.get('action')
    
    # Fallback to top-level action if present
    if not action:
        action = event.get('action')
        
    if action:
        actions[action.lower()] += 1
            
    proto = event.get('proto')
    if proto:
        protocols[proto.upper()] += 1
        
    app_proto = event.get('app_proto')
    if app_proto:
        protocols[app_proto.upper()] += 1

def get_recent_events(n=20, file_path=None):
    """
    Returns the last n events of type 'alert' from eve.json.
    """
    if file_path is None:
        file_path = DEFAULT_EVE_PATH

    if not os.path.exists(file_path):
        return []

    events = []
    lines_read = 0
    # We might need to read more than n lines to find n alerts
    # but we'll limit the search to max_search_lines to avoid infinite loop or high CPU
    max_search_lines = n * 50 
    
    with open(file_path, 'rb') as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        buffer = bytearray()
        pointer = file_size
        
        while pointer > 0 and len(events) < n and lines_read < max_search_lines:
            chunk_size = min(pointer, 4096)
            pointer -= chunk_size
            f.seek(pointer)
            chunk = f.read(chunk_size)
            buffer = chunk + buffer
            
            while b'\n' in buffer and len(events) < n and lines_read < max_search_lines:
                last_newline_idx = buffer.rfind(b'\n')
                line = buffer[last_newline_idx+1:].decode('utf-8', errors='ignore').strip()
                buffer = buffer[:last_newline_idx]
                
                if line:
                    try:
                        event = json.loads(line)
                        lines_read += 1
                        if event.get('event_type') == 'alert':
                            alert_data = {
                                'timestamp': event.get('timestamp'),
                                'src_ip': event.get('src_ip'),
                                'dest_ip': event.get('dest_ip'),
                                'dest_port': event.get('dest_port'),
                                'proto': event.get('proto'),
                                'message': event.get('alert', {}).get('signature', 'No message'),
                                'action': event.get('alert', {}).get('action'),
                                'sid': event.get('alert', {}).get('signature_id')
                            }
                            events.append(alert_data)
                    except json.JSONDecodeError:
                        pass
            
            if pointer == 0 and buffer and len(events) < n and lines_read < max_search_lines:
                line = buffer.decode('utf-8', errors='ignore').strip()
                if line:
                    try:
                        event = json.loads(line)
                        lines_read += 1
                        if event.get('event_type') == 'alert':
                            alert_data = {
                                'timestamp': event.get('timestamp'),
                                'src_ip': event.get('src_ip'),
                                'dest_ip': event.get('dest_ip'),
                                'dest_port': event.get('dest_port'),
                                'proto': event.get('proto'),
                                'message': event.get('alert', {}).get('signature', 'No message'),
                                'action': event.get('alert', {}).get('action'),
                                'sid': event.get('alert', {}).get('signature_id')
                            }
                            events.append(alert_data)
                    except json.JSONDecodeError:
                        pass
                buffer = bytearray()

    return events
