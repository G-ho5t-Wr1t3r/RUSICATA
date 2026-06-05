# Progetto Rusicata: Overview Tecnica

Rusicata è un'applicazione web basata su **Django** progettata per fungere da pannello di controllo semplificato (frontend) per **Suricata**, configurato in modalità **IPS (Intrusion Prevention System)**. Sviluppato per contesti di CyberChallenge, permette di gestire dinamicamente regole di filtraggio del traffico HTTP per diversi servizi.

## 1. Architettura del Sistema

Il progetto è strutturato come un'applicazione Django standard, con una logica di business fortemente integrata con il file system del sistema operativo per la gestione delle configurazioni di Suricata.

### 1.1 Struttura del Repository
- `rusicata_master/`: Contiene il progetto Django principale.
  - `rusicata/`: Impostazioni del progetto (`settings.py`, `urls.py`).
  - `rusicata_manager/`: App Django che gestisce la logica di controllo di Suricata.
- `setup.sh`: Script di automazione per il deploy completo sulla Game VM.
- `suricata.yaml`: Configurazione base di Suricata ottimizzata per la modalità IPS.

## 2. Dettagli Implementativi Django

### 2.1 Middleware di Sicurezza (`rusicata_manager/middleware.py`)
L'applicazione implementa un `TeamIPWhitelistMiddleware` che filtra l'accesso al pannello di controllo. Solo gli IP inclusi nella lista `TEAM_ALLOWED_IPS` (definita in `settings.py`) possono accedere alle funzionalità di amministrazione.

### 2.2 Modelli di Dati (`rusicata_manager/models.py`)

#### Service
Rappresenta un servizio da proteggere (es. una challenge CTF).
- **Attributi:** `name`, `port`.
- **Logica (`save`):** Al momento della creazione di un servizio, viene generato un file di regole dedicato in `/var/lib/suricata/rules/{name}.rules` e il file `suricata.yaml` viene aggiornato per includerlo. Segue un riavvio del demone Suricata.

#### HttpRule
Rappresenta una regola specifica di filtraggio HTTP.
- **Attributi:** `action` (alert, drop, reject), `protocol`, `message`, `request_method`, `content`, `content_location` (uri, body, header).
- **Logica di Generazione:** Il metodo `rulify` trasforma l'istanza del modello in una stringa compatibile con la sintassi di Suricata.
- **Interazione con Suricata:** Quando una regola viene creata, modificata o eliminata, il file `.rules` del servizio corrispondente viene aggiornato e viene inviato un segnale `USR2` al processo Suricata per l'hot-reload delle regole (senza riavviare l'intero demone).

## 3. Configurazione Suricata e IPS

### 3.1 Modalità IPS (NFQUEUE)
Suricata viene eseguito con l'opzione `-q 0`, che lo istruisce ad ascoltare sulla coda NFQUEUE numero 0 gestita da `iptables`.

**Regole Iptables iniettate (`setup.sh`):**
```bash
iptables -I DOCKER-USER -j NFQUEUE --queue-num 0 --queue-bypass
iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass
iptables -I INPUT -j NFQUEUE --queue-num 0 --queue-bypass
iptables -I OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass
```

### 3.2 Percorsi dei File
- **Regole:** `/var/lib/suricata/rules/`
- **Configurazione:** `/etc/suricata/suricata.yaml`
- **Log (EVE):** `/var/log/suricata/eve.json` (usato per il monitoraggio degli alert).

## 4. Deployment e Setup

Lo script `setup.sh` automatizza le seguenti operazioni:
1. Aggiornamento sistema e installazione dipendenze (`python3-venv`, `suricata`, `jq`).
2. Configurazione dell'ambiente virtuale Python e installazione dei requirements.
3. Configurazione di Django (migrazioni, creazione superuser).
4. Configurazione del demone Suricata come servizio di sistema in modalità IPS.
5. Iniezione delle regole `iptables`.
6. Avvio di Rusicata sulla porta 8000.

## 5. Note Operative e Troubleshooting

### 5.1 Problemi Noti
- **IP Masking:** In ambienti simulati (es. Tailscale/Wireguard), il middleware potrebbe vedere l'IP del gateway invece di quello reale del player. È stata introdotta una variabile `SIMULATION` in `settings.py` per gestire queste eccezioni.
- **Testing Locale:** Le regole `drop` potrebbero non funzionare se il traffico viene generato da `localhost` verso `localhost` a causa del modo in cui `iptables` gestisce l'interfaccia di loopback.
- **Formattazione YAML:** Errori di formattazione automatica in `suricata.yaml` possono impedire il riavvio del demone. Si raccomanda di verificare sempre con `suricata -T`.

### 5.2 Comandi Utili
- Riavvio Suricata: `sudo systemctl restart suricata`
- Monitoraggio Log: `tail -f /var/log/suricata/eve.json | jq`
- Controllo Stato: `suricatasc -c reload-rules` (se il socket Unix è attivo).

