# Branch file
In questo file raggrupperemo tutte le modifiche e le osservazioni fatte in fase di testing e simulazione.

## SESSIONE 16-04-2026
Runnando rusicata in simulazione su rete tailscale in combo con wireguard abbiamo notato che il middleware non riesce a prendere l'ip reale del player.
```
ip = request.META.get('REMOTE_ADDR')
```
\*Riga 9 file middleware.py

Ho modificato il file settings per "risolvere" momentaneamente questo problema.

```
DEBUG = True
SIMULATION = True

# ============================
# MODIFY THIS:
PLAYER_1 = '0.0.0.0'
PLAYER_2 = '0.0.0.0'
PLAYER_3 = '0.0.0.0'
PLAYER_4 = '0.0.0.0'   
PLAYER_5 = '0.0.0.0'
PLAYER_6 = '0.0.0.0'
# ============================

ALLOWED_HOSTS = ['*']
if not SIMULATION:
    TEAM_ALLOWED_IPS = ['127.0.0.1', PLAYER_1, PLAYER_2, PLAYER_3, PLAYER_4, PLAYER_5, PLAYER_6]
else:
    TEAM_ALLOWED_IPS = ['127.0.0.1', '10.80.253.253'] 
```

L'ip `10.80.253.253` è quello del nostro "proxy" tailscale.

