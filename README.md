# Rusicata

<center><img src=".assets/logo.jpg" width="700" height="350"></center>

<details>
  <summary><b>IT</b></summary>

## Overview

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

## 3. Scelte di Progettazione

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

## Licenza
Questo progetto è concesso in licenza ai sensi della [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).
Ciò significa che sei libero di condividere e modificare il materiale, a condizione che tu mi attribuisca il merito, non lo utilizzi per scopi commerciali e distribuisca eventuali versioni modificate sotto la stessa licenza.

</details>

<details open>
  <summary><b>EN</b></summary>
## Overview

Rusicata is an advanced **Django**-based solution for simplified management of **Suricata** in **IPS (Intrusion Prevention System)** mode. Designed specifically for Attack & Defense (A/D) competitions, Rusicata allows you to protect services through dynamic rules, real-time monitoring, and granular management of HTTP and transport traffic.

---

## 1. Introduction to Suricata IPS

Suricata is a high-performance network security monitoring engine (IDS/IPS). In IPS mode, Suricata does not merely detect threats but can **actively intervene** (drop/reject) to block malicious traffic.

### How Rules Work
Suricata rules follow a specific syntax consisting of:
`action protocol source_port -> destination destination_port (options)`

**Examples of rules managed by Rusicata:**

1.  **HTTP Filter (URI Match):**
    `drop http any any -> any 80 (msg:“Blocking SQLi attack”; flow:to_server,established; content:‘GET’; http_method; content:“UNION SELECT”; http_uri; sid:100001; rev:1;)`
2.  **Transport Filter (TCP):**
    `alert tcp any any -> any 4444 (msg:“Suspicious traffic detected on port 4444”; flow:to_server,established; sid:100002; rev:1;)`
3.  **Global Filter (ICMP):**
    `reject icmp any any -> any any (msg:“Ping disabled”; sid:2000001; rev:1;)`

---

## 2. Repository Structure

The project is organized to separate the web management logic from the system configuration:

*   **`rusicata_master/`**: Core of the Django project.
    *   **`rusicata/`**: Global configurations (`settings.py`, `urls.py`).
    *   **`rusicata_manager/`**: Main application. Contains the models (`models.py`), the dashboard views, and the logic for interacting with Suricata.
    *   **`suricata.yaml`**: Suricata configuration template optimized for Rusicata.
*   **`init.sh`**: Local script for packaging and transferring the project to the Game VM.
*   **`setup.sh`**: Remote script for installing dependencies and performing a full deployment.
*   **`destroy_rusicata.sh`**: Script for a full system rollback (removal of Suricata, iptables rules, and data).
*   **`.assets/`**: Graphic resources for the documentation.

---

## 3. Design Choices

### Django-System Integration
Unlike a standard web app, Rusicata interacts directly with the operating system:
*   **Rule File Management**: Each `Service` created in the database generates a physical file at `/var/lib/suricata/rules/{service_name}.rules`.
*   **Hot-Reload**: To avoid service interruption, Rusicata uses `SIGUSR2` signals to instruct Suricata to reload the rules without restarting the daemon. A full restart (`systemctl restart`) is performed only when the file structure is modified (e.g., adding a new service).
*   **SID Management**: Rule IDs (SIDs) are automatically generated using an offset based on the service ID (e.g., `Service ID * 100000 + increment`) to ensure uniqueness.

### Asynchronous Logic
Heavy operations such as restarting the Suricata daemon are handled via separate threads (`threading.Thread`) to ensure that the web interface remains responsive during maintenance operations.

---

## 4. Automation and Scripts

### 4.1 `init.sh` (Local Management)
Automates the transfer of files to the destination VM.
*   **Compression**: Creates a tarball named `rusicata.tar.gz`, excluding unnecessary files (`env`, `__pycache__`, `.git`).
*   **Transfer**: Sends the tarball and the `setup.sh` script via SCP.
*   **Debug Mode**: If run with `-D`, it also transfers the maintenance scripts (`destroy_rusicata.sh`).

### 4.2 `setup.sh` (Deployment)
Performs the complete setup on the VM:
1.  **Dependencies**: Installs `python3-venv`, `suricata`, `jq`, and `software-properties-common`.
2.  **Python Environment**: Creates a virtual environment and installs the requirements.
3.  **Django Setup**: Configures the SQLite database, applies migrations, and creates the superuser (default `root:root`).
4.  **Suricata Config**: Configure the daemon as a system service in IPS mode (`-q 0`).
5.  **Networking**: Inject the necessary IPTABLES rules to route traffic to the Suricata queue.

### 4.3 `destroy_suricata.sh` (Purge)
Restores the machine to its initial state:
*   Stops Django and Suricata.
*   Completely removes the Suricata packages and related configurations in `/etc/suricata`.
*   **Cleans up IPTABLES**: Surgically removes the rules that jump to NFQUEUE.
*   Deletes the `/opt/rusicata` directory and the database.

---

## 5. Networking and IPS Configuration (NFQUEUE)

Suricata in IPS mode acts as a “filter” between the network interfaces and the applications.

### Choosing IPTABLES Chains
Traffic is sent to Suricata via the `NFQUEUE 0` queue. The configuration depends on the type of traffic to be inspected:

*   **Standard Mode (`DOCKER-USER`)**: Inspects only traffic directed to Docker containers. This is the most performant and secure choice in CTF contexts where services are containerized.
*   **Full Mode (`--all`)**: Involves the `INPUT`, `FORWARD`, and `OUTPUT` chains. It inspects all traffic on the machine, including SSH access and system communications.

**Note on Docker’s DNAT:**
Docker applies NAT in the `PREROUTING` chain. When a packet reaches the `FORWARD` (or `DOCKER-USER`) chain, the destination port has already been mapped to the container’s internal port. **Rusicata rules must therefore be based on the actual port on which the application is running inside the container.**

---

## 6. Manual Setup (Step-by-Step)

If you want to install Rusicata without the automation scripts:

### Step 1: System Preparation
```bash
sudo apt update && sudo apt install -y python3-venv suricata jq
```

### Step 2: Django Configuration
1.  Extract the code to `/opt/rusicata`.
2.  Create the venv: `python3 -m venv .env && source .env/bin/activate`.
3.  Install dependencies: `pip install -r requirements.txt`.
4.  Configure the database:
    ```bash
    python3 rusicata_master/manage.py migrate
    python3 rusicata_master/manage.py createsuperuser
    ```

### Step 3: Suricata Configuration
1.  Copy `rusicata_master/suricata.yaml` to `/etc/suricata/suricata.yaml`.
2.  Edit the systemd service (`/usr/lib/systemd/system/suricata.service`) by setting:
    `ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 0 -D`
3.  Reload and restart: `systemctl daemon-reload && systemctl restart suricata`.

### Step 4: IPTABLES
Configure the redirection:
```bash
iptables -I DOCKER-USER -j NFQUEUE --queue-num 0 --queue-bypass
```

---

## 7. Operational Notes and Troubleshooting

### Useful Commands
*   **Event Monitoring**: 
```
tail -f /var/log/suricata/eve.json | jq
```
*   **Configuration Check**: 
```
suricata -T -c /etc/suricata/suricata.yaml
```
*   **Rule Status** (requires an active Unix socket):
```
suricatasc -c reload-rules
```

### Known Issues
*   **Loopback Testing**: Iptables does not process traffic from `localhost` to `localhost` in the same way as external traffic; `drop` tests may fail when run locally.
*   **YAML Syntax**: Suricata is extremely sensitive to the formatting of the `suricata.yaml` file. Indentation errors will prevent the service from starting.

## License
This project is licensed under the [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).
This means you are free to share and modify the material, provided that you give me credit, do not use it for commercial purposes, and distribute any modified versions under the same license.
</details>

