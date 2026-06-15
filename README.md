# Rusicata

<center><img src=".assets/logo.jpg" width="700" height="350"></center>

Rusicata è una soluzione avanzata basata su **Django** per la gestione semplificata di **Suricata** in modalità **IPS (Intrusion Prevention System)**. Progettato specificamente per competizioni di tipo Attack & Defense (A/D), Rusicata permette di proteggere i servizi tramite regole dinamiche, monitoraggio in tempo reale e una gestione granulare del traffico HTTP e di trasporto.

---

## 1. Introduzione a Suricata IPS

Suricata è un motore di monitoraggio della sicurezza di rete (IDS/IPS) ad alte prestazioni. In modalità IPS, Suricata non si limita a rilevare le minacce, ma può **intervenire attivamente** (drop/reject) sul traffico malevolo.

### Funzionamento delle Regole
Le regole di Suricata seguono una sintassi specifica composta da:
`azione protocollo sorgente porta_sorgente -> destinazione porta_destinazione (opzioni)`

**Esempi di regole gestite da Rusicata:**

1.  **Filtro HTTP (corrispondenza nell'URI):**
    `drop http any any -> any 80 (msg:"Blocco attacco SQLi"; flow:to_server,established; content:"GET"; http_method; content:"UNION SELECT"; http_uri; sid:100001; rev:1;)`
2.  **Filtro di Trasporto (TCP):**
    `alert tcp any any -> any 4444 (msg:"Rilevato traffico sospetto su porta 4444"; flow:to_server,established; sid:100002; rev:1;)`
3.  **Filtro Globale (ICMP):**
    `reject icmp any any -> any any (msg:"Ping disabilitato"; sid:2000001; rev:1;)`

---

## 2. Struttura del Repository

Il progetto è organizzato per separare la logica di gestione web dalla configurazione di sistema:

*   **`rusicata_master/`**: Core del progetto Django.
    *   **`rusicata/`**: Configurazioni globali (`settings.py`, `urls.py`).
    *   **`rusicata_manager/`**: Applicazione principale. Contiene i modelli (`models.py`), le view per il dashboard e la logica di interazione con Suricata.
    *   **`suricata.yaml`**: Template di configurazione per Suricata ottimizzato per Rusicata.
*   **`init.sh`**: Script locale per l'impacchettamento e il trasferimento del progetto sulla Game VM.
*   **`setup.sh`**: Script remoto per l'installazione delle dipendenze e il deploy completo.
*   **`destroy_rusicata.sh`**: Script per il ripristino totale del sistema (rimozione di Suricata, regole iptables e dati).
*   **`.assets/`**: Risorse grafiche per la documentazione.

---

## 3. Scelte di Progettazione del Codice

### Integrazione Django-Sistema
A differenza di un'app web standard, Rusicata interagisce direttamente con il sistema operativo:
*   **Gestione File di Regole**: Ogni `Service` creato nel database genera un file fisico in `/var/lib/suricata/rules/{service_name}.rules`.
*   **Hot-Reload**: Per evitare l'interruzione del servizio, Rusicata utilizza segnali `SIGUSR2` per istruire Suricata di ricaricare le regole senza riavviare il demone. Il riavvio completo (`systemctl restart`) viene eseguito solo quando viene modificata la struttura dei file (es. aggiunta di un nuovo servizio).
*   **SID Management**: Gli ID delle regole (SID) sono generati automaticamente utilizzando un offset basato sull'ID del servizio (es. `Service ID * 100000 + increment`) per garantire l'univocità.

### Logica Asincrona
Operazioni pesanti come il riavvio del demone Suricata sono gestite tramite thread separati (`threading.Thread`) per garantire che l'interfaccia web rimanga reattiva durante le operazioni di manutenzione.

---

## 4. Automazione e Script

### 4.1 `init.sh` (Local Management)
Automatizza il trasferimento dei file verso la VM di destinazione.
*   **Compressione**: Crea un tarball `rusicata.tar.gz` escludendo file non necessari (`env`, `__pycache__`, `.git`).
*   **Trasferimento**: Invia via SCP il tarball e lo script `setup.sh`.
*   **Debug Mode**: Se avviato con `-D`, trasferisce anche gli script di manutenzione (`destroy_rusicata.sh`).

### 4.2 `setup.sh` (Deployment)
Esegue il setup completo sulla VM:
1.  **Dipendenze**: Installa `python3-venv`, `suricata`, `jq` e `software-properties-common`.
2.  **Python Environment**: Crea un virtual environment e installa i requisiti.
3.  **Django Setup**: Configura il database SQLite, applica le migrazioni e crea il superuser (default `root:root`).
4.  **Suricata Config**: Configura il demone come servizio di sistema in modalità IPS (`-q 0`).
5.  **Networking**: Inietta le regole IPTABLES necessarie per instradare il traffico verso la coda di Suricata.

### 4.3 `destroy_rusicata.sh` (Purge)
Ripristina lo stato iniziale della macchina:
*   Arresta Django e Suricata.
*   Rimuove completamente i pacchetti di Suricata e le relative configurazioni in `/etc/suricata`.
*   **Pulisce IPTABLES**: Rimuove chirurgicamente le regole di salto verso NFQUEUE.
*   Elimina la directory `/opt/rusicata` e il database.

---

## 5. Configurazione Networking e IPS (NFQUEUE)

Suricata in modalità IPS agisce come un "filtro" tra le interfacce di rete e le applicazioni.

### Scelta delle Chain IPTABLES
Il traffico viene inviato a Suricata tramite la coda `NFQUEUE 0`. La configurazione dipende dal tipo di traffico da ispezionare:

*   **Modalità Standard (`DOCKER-USER`)**: Ispeziona solo il traffico diretto ai container Docker. È la scelta più performante e sicura in contesti CTF dove i servizi sono containerizzati.
*   **Modalità Full (`--all`)**: Coinvolge le chain `INPUT`, `FORWARD` e `OUTPUT`. Ispeziona tutto il traffico della macchina, inclusi accessi SSH e comunicazioni di sistema.

**Attenzione al DNAT di Docker:**
Docker applica il NAT nella chain `PREROUTING`. Quando un pacchetto arriva alla chain `FORWARD` (o `DOCKER-USER`), la porta di destinazione è già stata trasformata in quella interna del container. **Le regole di Rusicata devono quindi basarsi sulla porta reale su cui gira l'applicazione nel container.**

---

## 6. Setup Manuale (Step-by-Step)

Se si desidera installare Rusicata senza gli script di automazione:

### Fase 1: Preparazione Sistema
```bash
sudo apt update && sudo apt install -y python3-venv suricata jq
```

### Fase 2: Configurazione Django
1.  Estrarre il codice in `/opt/rusicata`.
2.  Creare il venv: `python3 -m venv .env && source .env/bin/activate`.
3.  Installare le dipendenze: `pip install -r requirements.txt`.
4.  Configurare il DB:
    ```bash
    python3 rusicata_master/manage.py migrate
    python3 rusicata_master/manage.py createsuperuser
    ```

### Fase 3: Configurazione Suricata
1.  Copiare `rusicata_master/suricata.yaml` in `/etc/suricata/suricata.yaml`.
2.  Modificare il servizio systemd (`/usr/lib/systemd/system/suricata.service`) impostando:
    `ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 0 -D`
3.  Ricaricare e avviare: `systemctl daemon-reload && systemctl restart suricata`.

### Fase 4: IPTABLES
Configurare il reindirizzamento:
```bash
iptables -I DOCKER-USER -j NFQUEUE --queue-num 0 --queue-bypass
```

---

## 7. Note Operative e Troubleshooting

### Comandi Utili
*   **Monitoraggio Eventi**: 
```
tail -f /var/log/suricata/eve.json | jq
```
*   **Verifica Configurazione**: 
```
suricata -T -c /etc/suricata/suricata.yaml
```
*   **Stato Regole** (richiede socket unix attivo):
```
suricatasc -c reload-rules
```

### Problemi Noti
*   **Loopback Testing**: Iptables non processa il traffico da `localhost` a `localhost` nello stesso modo del traffico esterno; i test di `drop` potrebbero fallire se eseguiti localmente.
*   **YAML Syntax**: Suricata è estremamente sensibile alla formattazione del file `suricata.yaml`. Errori di indentazione impediranno l'avvio del servizio.
