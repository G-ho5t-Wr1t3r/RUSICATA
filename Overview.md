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

### 2.1 Modelli di Dati (`rusicata_manager/models.py`)

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

### 5.2 Problemi Noti
- **Testing Locale:** Le regole `drop` potrebbero non funzionare se il traffico viene generato da `localhost` verso `localhost` a causa del modo in cui `iptables` gestisce l'interfaccia di loopback.
- **Formattazione YAML:** Errori di formattazione automatica in `suricata.yaml` possono impedire il riavvio del demone. Si raccomanda di verificare sempre con `suricata -T`.

### 5.3 Configurazione di IPTABLES

Le regole iniettate da `setup.sh` instradano il traffico verso Suricata tramite **NFQUEUE**. La scelta di quali chain configurare non è arbitraria e ha implicazioni importanti.

#### Comportamento del DNAT di Docker

Quando un container espone una porta (es. `0.0.0.0:80->1234/tcp`), Docker inserisce automaticamente una regola di **DNAT** nella chain `nat/PREROUTING`. Questo significa che il pacchetto viene rediretto **prima** che qualsiasi chain della tabella `filter` lo veda:

```
Pacchetto in arrivo (dst: host:80)
         │
         ▼
[ nat/PREROUTING ]  ← Docker applica DNAT: dst:80 → container_ip:1234
         │
         ▼
[ filter/FORWARD ]  ← il pacchetto ha già dst port 1234, non 80
     └─ DOCKER-USER
     └─ DOCKER
```

**Conseguenza pratica:** eventuali regole Suricata che matchano sulla porta esposta dall'host (es. 80) non avranno effetto. Bisogna usare la porta **interna** del container (es. 1234).

#### DOCKER-USER vs FORWARD/INPUT/OUTPUT

| Configurazione | Traffico catturato |
|---|---|
| Solo `DOCKER-USER` | Tutto il traffico Docker (sottoinsieme di FORWARD) |
| `FORWARD` + `INPUT` + `OUTPUT` | Tutto il traffico della macchina (Docker incluso) |
| Tutte e 4 insieme | Il traffico Docker passa in NFQUEUE **due volte** ⚠️ |

Le due configurazioni sono **mutualmente esclusive**:

- Usare `DOCKER-USER` se si vuole ispezionare **solo** il traffico dei container (più leggero).
- Usare `FORWARD` + `INPUT` + `OUTPUT` se si vuole ispezionare **tutto** il traffico della macchina, Docker compreso.

Non vanno mai usate contemporaneamente.

#### Verifica dello stato attuale

```bash
# Controllare le regole attive sulla tabella filter
iptables -L -n --line-numbers

# Verificare il DNAT applicato da Docker
iptables -t nat -L PREROUTING -n --line-numbers

# Rimuovere una regola per numero di linea (es. riga 1 di FORWARD)
iptables -D FORWARD 1
```


### 5.4 Comandi Utili
- Riavvio Suricata: `sudo systemctl restart suricata`
- Monitoraggio Log: `tail -f /var/log/suricata/eve.json | jq`
- Controllo Stato: `suricatasc -c reload-rules` (se il socket Unix è attivo).

