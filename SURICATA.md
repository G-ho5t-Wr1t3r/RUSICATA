# SURICATA

Vedi: [opzioni da riga di comando](https://docs.suricata.io/en/suricata-8.0.4/command-line-options.html)
`-T` test configurazione
`-v, -vv, -vvv` verbosità
`-r <path>` replay mode from pcap
	- Ci sono varie opzioni per usare i pcap in replay mode
`-i <interface>` set network interface
`-q <num>` **attiva la modalità ips** 
- se ti trovi in cattura con NFQUEUE. Dice a suricata di prendere i pacchetti dalla coda di NFQUEUE e analizzarli. Si può configurare iptables per avere più code NFQUEUE e quindi far lavorare suricata contemporaneamente su più code
- `iptables -A FORWARD -j NFQUEUE --queue-num 0 --queue-bypass` Si usa queue bypass in modo che se iptables rileva che nessun processo sta leggendo i pacchetti dalla coda i pacchetti vengono fatti passare di default, ergo **se suricata va in crash la rete non si blocca**

`-D` Lancia suricata come demone

`-s <file.rules>` modalità **additiva**: carica le regole del file indicato _in aggiunta_ a quelle già definite nel `suricata.yaml`. Supporta il globbing (`-s '/path/*.rules'`).
`-S <file.rules>` modalità **esclusiva**: carica _solo_ le regole specificate nel flag. Ignora completamente la sezione `rule-files` del file `.yaml`. Utile per debugging o analisi mirate. 

`--pidfile <file>` L'opzione serve a specificare dove Suricata deve scrivere il proprio **PID** (Process ID).
- **Controllo**: Permette a script esterni o al sistema (es. `systemd`) di sapere esattamente quale processo terminare o riavviare.
- **Prevenzione**: Impedisce di avviare accidentalmente due istanze di Suricata contemporaneamente sulla stessa configurazione/interfaccia (il cosiddetto "locking").
- È fondamentale quando automatizzi Suricata. Se devi aggiornare le regole e vuoi ricaricarle senza spegnere il motore (invio di un segnale `USR2`), lo script userà il file indicato per trovare il processo corretto: `kill -USR2 $(cat /var/run/suricata.pid)`


`--dump-config` Dump the configuration loaded from the configuration file to the terminal and exit.
`--simulate-ips` Simula modalità IPS quando si è in una modalità non-IPS

## Cattura con AF_PACKET e NF_QUEUE
**Utilizzeremo NF_QUEUE**
NF_QUEUE lavora in combinazione con iptables, il traffico viene passato a una chain gestita da suricata.

La cattura con AF_PACKET è più veloce in vari modi ma richiede che il traffico passi da 
`interfaccia di rete A ->  SURICATA -> interfaccia di rete B`

### Regole iptables
La NFQUEUE di base blocca tutto il traffico. **Vogliamo impostare la cattura in NFQUEUE solo sulle porte dei nostri servizi**

- Dobbiamo assicurarci che la regola NFQUEUE venga messa al primo posto nella catena usando -I non -A
- Usa `iptables dump` per vedere tutte le regole

## Logging (IPS Mode)

_I log si trovano solitamente in `/var/log/suricata/`._

- **eve.json** (Principale): log omnicomprensivo in formato JSON. Indispensabile per SIEM/analisi automatizzata.
    
    - **In IPS**: Fondamentale controllare il campo `"action": "blocked"` per confermare il drop del pacchetto.
        
- **fast.log**: log testuale sintetico. Mostra solo gli alert (chi, cosa, dove). Utile per monitoraggio rapido da terminale (`tail -f`).
    
- **suricata.log**: log di sistema del motore. Da controllare se Suricata non parte o crasha (errori di configurazione o memoria).
    
- **stats.log**: statistiche periodiche sulle performance. In IPS monitora `decoder.pkts` e `drop` per verificare il carico sulle code.

## suricatasc
**suricatasc**: Tool di controllo via Unix Socket.

- `suricatasc -c rules-reload`: Metodo preferito per ricaricare le regole (rispetto a `kill -USR2`) perché fornisce un feedback di successo/errore.
    
- **Vantaggio IPS**: Permette di interrogare lo stato delle code e dei contatori in tempo reale senza interrompere il traffico.
    
- **Nota**: Richiede che nel `suricata.yaml` sia abilitata la sezione `unix-command: enabled: yes`.

### Altre funzioni utili di `suricatasc`

Oltre al reload, con questo tool puoi fare cose che il segnale `kill` non permette:

- **suricatasc -c status**: Ti dice se il motore è attivo e funzionante.
    
- **suricatasc -c uptime**: Ti dice da quanto tempo Suricata è in esecuzione.
    
- **suricatasc -c version**: Controlla la versione del processo in esecuzione.
    
- **suricatasc -c iface-list**: Mostra le interfacce che Suricata sta monitorando attualmente.
    
- **suricatasc -c dump-counters**: Ti restituisce tutte le statistiche di traffico correnti (pacchetti letti, droppati, ecc.) senza dover aspettare che vengano scritte nello `stats.log`.

