# Appunti su Suricata

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

# Antonio
REGOLA CHE BLOCCA TUTTO IL TRAFFICO SU UNA PORTA
drop tcp any any -> any 3000 (msg:"MIAO >^.^<_POST_BLOCK"; sid:600003; rev:1;)
