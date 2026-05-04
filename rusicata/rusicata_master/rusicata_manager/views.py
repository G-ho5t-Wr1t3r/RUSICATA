import subprocess
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from . import telemetry

def index(request):
    return render(request, 'rusicata_manager/index.html')

@login_required
def dashboard(request):
    # Check if Suricata is running
    try:
        subprocess.run(['pidof', 'suricata'], check=True, stdout=subprocess.DEVNULL)
        status = 'Active'
    except subprocess.CalledProcessError:
        status = 'Inactive'
    except FileNotFoundError:
        status = 'Inactive (pidof not found)'

    stats = telemetry.get_stats()
    recent_events = telemetry.get_recent_events(n=20)

    context = {
        'status': status,
        'stats': stats,
        'recent_events': recent_events,
    }
    return render(request, 'rusicata_manager/dashboard.html', context)

