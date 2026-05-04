# Appunti su Suricata

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

## SESSIONE 30-04-2026
A quanto pare suricata estrae i cookie in maniera completamente separata dagli header, quindi per bloccare uno specifico cookie bisogna usare
```
http_cookie
```

Ad esempio:
```
drop http any any -> any 8080 (msg:"MIAO >^.^<"; flow:to_server,established; content:"GET"; http_method; content:"user_hash"; http_cookie; sid:600001; rev:2;)
```

### Perché le regole non sembrano funzionare?
Lo script `setup.sh` automatizza l'installazione di Ruasicta. Nel farlo, lo script configura esplicitamente il motore per funzionare come IPS (Intrusion Prevention System) attivo.  

Ecco il perché del comportamento misterioso:
- L'avvio in IPS: Lo script altera il demone suricata.service inserendo l'istruzione `ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 0 -D`.  
- Significato tecnico: Questo comando obbliga Suricata ad ascoltare esclusivamente la coda zero di iptables, scollegandolo dalle classiche interfacce di rete.  
- Il firewall: Lo script inietta regole in iptables per intercettare il traffico (DOCKER-USER, FORWARD, INPUT, OUTPUT) e spedirlo alla `NFQUEUE --queue-num 0 --queue-bypass`.  

Quindi la configurazione della Game VM è tecnicamente ineccepibile per bloccare il traffico (azione drop)! Se generiamo il traffico con Netcat dalla VM verso se stessa 
(usando localhost o 127.0.0.1), il flusso viaggia sull'anello virtuale di loopback (lo). 
Iptables gestisce il loopback in modo speciale, bypassando spesso gli hook che mandano i pacchetti verso la NFQUEUE. 
In breve: la regola c'è, ma il pacchetto di test locale la schiva.

Potrebbe essere legato a quel problema del masking degli ip?

### Cosa fare dopo aver scritto una regola?
Dopoa ver scritto una nuova regola bisognerà restartare il demone:
```
sudo systemctl restart suricata
```

### Resoconto Sessione 
Abbiamo notato che nonostante l'inserimento di regole come:
```
# File /var/lib/suricata/rules/CCalendar.rules
drop http any any -> any 8080 (msg:"MIAO >^.^<"; flow:to_server,established; content:"GET"; http_method; content:"user_hash"; http_cookie; sid:600001; rev:2;)
alert http any any -> any 8080 (msg:"MIAO >^.^<"; content:"GET"; http_method; content:"user_hash"; http_cookie; sid:600001; rev:3;)
drop http any any -> any 8080 (msg:"MIAO >^.^<_POST_BLOCK"; content:"POST"; http_method; content:"username="; http_client_body; sid:600002; rev:1;)
```

```
# File /var/lib/suricata/rules/PCSS.rules 
drop tcp any any -> any 3000 (msg:"MIAO >^.^<_NETCAT_BLOCK"; sid:600003; rev:1;)
```

Le regole non sembrano aver prodotto alcun tipo di risultato.

#### Troubleshooting
I test eseguiti per verificare il corretto funzionamento e settaggio sono stati i seguenti:

Per vedere in tempo reale le risposte di rusicata
```
 root@vm1:/var/lib/suricata/rules# sudo tail -f /var/log/suricata/fast.log | grep "MIAO >^.^<"



```

Per vedere i file mappati come file delle regole
```
root@vm1:/var/lib/suricata/rules# grep -A 5 "rule-files:" /etc/suricata/suricata.yaml
rule-files:
- suricata.rules
- CCalendar.rules
- PCSS.rules
security:
  landlock:
```

Per verificare la presenza del file di log
```
root@vm1:/var/lib/suricata/rules# ps aux | grep suricata
root        5505  0.0  0.2  19788  7144 ?        S    17:43   0:00 sudo tail -f /var/log/suricata/fast.log
root        5507  0.0  0.0  19788  2704 pts/4    Ss+  17:43   0:00 sudo tail -f /var/log/suricata/fast.log
root        5508  0.0  0.0   8744  1872 pts/4    T    17:43   0:00 tail -f /var/log/suricata/fast.log
root        7331  0.0  1.7 680408 54416 ?        Ssl  17:59   0:06 /usr/bin/suricata -c /etc/suricata/suricata.yaml -q 0 -D
root        8554  0.0  0.0   9144  2324 pts/1    S+   18:11   0:00 grep --color=auto suricata
```

Da qui abbiamo capito che il file di log è eve.json, infatti fast.log è deprecato da un po'...
```
drwxrwxr-x 1 root     suricata    0 Mar 17 12:45 certs
drwxrwxr-x 1 root     suricata    0 Mar 17 12:45 core
-rw-r--r-- 1 suricata suricata 4.9M Apr 30 18:03 eve.json
-rw-r--r-- 1 suricata suricata    0 Apr 30 16:53 fast.log
drwxrwxr-x 1 root     suricata    0 Mar 17 12:45 files
-rw-r--r-- 1 suricata suricata 1.5M Apr 30 18:03 stats.log
-rw-r--r-- 1 suricata suricata  23K Apr 30 17:59 suricata.log
```

Il comando che ci ha fatto decidere di chiudere per oggi:
```
 root@vm1:/var/lib/suricata/rules# sudo tail -f /var/log/suricata/eve.json | grep "MIAO >^.^<"



```

#### Conclusione
Abbiamo deciso di risolvere il problema relativo al mascheramento dell'IP (già risolto per un'altra simulazione, ma per ragioni di tempo impossibile da fare adesso: comporterebbe il rebuild di tutte le macchine). Dopo aver risolto il problema effettueremo nuovamente dei test escludendo la possibilità di abiguità legate a questo problema.

## SESSIONE 03-05-2026
Oggi tramite una regola scritta a mano siamo riusciti a bloccare tutto il traffico su una specifica port:
```
drop tcp any any -> any 3000 (msg:"MIAO >^.^<_POST_BLOCK"; sid:600003; rev:1;)
```

Si è proseguito tentando di bloccare tutto il traffico in ingresso alla porta 8443 per evitare di contattare il servizio CCalendar

```
drop tcp any any -> 10.60.1.1 8443 (msg:"CCalendar TEST"; sid:1000001; rev:1;)
drop udp any any -> 10.60.1.1 8443 (msg:"CCalendar TEST"; sid:1000002; rev:1;)
```

Tuttavia le regole non sembrano funzionare:

| Comando | Azione |
| -------------- | -------------- |
| ```systemctl status suricata``` | Verifica lo stato di suricata |
| ```journalctl -u suricata --no-pager \| tail -n 20``` | Visualizza i log recenti per il servizio|
| ```grep -A 3 ""unix-command"" /etc/suricata/suricata.yaml```| Verifica la configurazione del socket Unix|
| ```tail -f /var/log/suricata/eve.json \| grep TEST``` | Visualizza i log dal file `eve.json` | 

Ho provato a fare anche altri test
```
root@vm1:~# grep "CCalendar.rules" /etc/suricata/suricata.yaml
root@vm1:~# sed -i '/rule-files:/a \ - /var/lib/suricata/rules/CCalendar.rules' /etc/suricata/suricata.yaml
root@vm1:~# suricatasc -c reload-rules
Unable to connect to socket /var/run/suricata-command.socket: L178: [Errno 111] Connection refused
root@vm1:~# grep "CCalendar.rules" /etc/suricata/suricata.yaml
 - /var/lib/suricata/rules/CCalendar.rules
root@vm1:~# tail -f /var/log/suricata/eve.json | grep TEST
^C
root@vm1:~# systemctl restart suricata
Job for suricata.service failed because the control process exited with error code.
See "systemctl status suricata.service" and "journalctl -xeu suricata.service" for details.
```

Visto l'errore di formattazione ho modificato il file a mano:
```
root@vm1:~# micro /etc/suricata/suricata.yaml
root@vm1:~# suricata -T -c /etc/suricata/suricata.yaml
i: suricata: This is Suricata version 7.0.3 RELEASE running in SYSTEM mode
i: suricata: Configuration provided was successfully loaded. Exiting.
```

Dentro lo yaml ho dovuto modificare la sezione `rule-files`:
```yaml
rule-files:
  - suricata.rules
  - CCalendar.rules
```

Poi ho restartato il servizio di suricata
```
systemctl restart suricata
```

Eh niente... il computer di Dome si è spento. Alla prossima! 