# RUSICATA

Rusicata è un frontend scritto in Django dagli studenti di cyberchallenge dell'Università della Calabria e manutenuto dagli stessi di anno in anno.

<aside>
💡 Rrusicata di default è in esecuzione sulla 8000. Se qualche servizio vulnerabile usa la stessa porta cambiare quella di rusicata quando si avvia.
</aside>

## Installazione
Di seguito i passaggi per il corretto funzionamento di Rusicata.

1. Creare un tar della cartella **Rusicata e copiarlo sulla game_vm**

```bash
tar czf rusicata.tar.gz rusicata/
scp rusicata.tar.gz root@<game_vm>:/opt
```

2. Sulla <game_vm>: 
    - scompattare la cartella compressa
    - creare un python venv
    - attivarlo ed 
    - installare i requirements.

```bash
cd /opt
tar xzf rusicata.tar.gz
cd rusicata
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt # A volte non funziona: PEP 668 
# Se non funziona usare il seguente comando
pip install -r requirements.txt --break-system-packages
```

## Configurazione di Rusicata

Modficare nel file [settings.py](http://settings.py) la lista di IP che possono accedere. NOTA: è stato **aggiunto un middleware** per verificare gli IP con una whitelist.

```bash
ALLOWED_HOSTS = ['*']
TEAM_ALLOWED_IPS = ['127.0.0.1', 'IP_player1', ... , 'IP_player6']
```

```bash
python3 manage.py createsuperuser # imposta username e password
```
 
# SURICATA
1. Installare **suricata** sulla game_vm

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata jq -y
suricata --build-info
```

1. Copia il file `suricata.yaml` (modifica se serve l’interfaccia di rete su cui si mette in ascolto, nella prima sezione del file) della cartella rusicata_master in `/etc/suricata/`

```bash
# N.B.: ora l'interfaccia di rete è settata su 'game' che va bene per le simulazioni

mv /var/lib/suricata/rules/suricata.rules /var/lib/suricata/rules/suricata.rules.old
touch /var/lib/suricata/rules/suricata.rules #NUOVO FILE

sudo suricata -T -c /etc/suricata/suricata.yaml -v #per testare se tutto ok
```

ATTENZIONE: 
In alcuni casi la catella `/var/lib/suricata/rules/suricata.rules` non è presente, come nella simulazione fatta su una ubuntu server stock.
I passi che ho seguito sono i seguenti:
```bash
mkdir -p /var/lib/suricata/rules
touch /var/lib/suricata/rules/suricata.rules #NUOVO FILE

sudo suricata -T -c /etc/suricata/suricata.yaml -v #per testare se tutto ok
```

2. Aggiungi le regole di firewall per eseguire suricata sulla game_vm in **modalità IPS**

```bash
# Se i servizi sono solo basati su docker basta usare SOLO QUESTA REGOLA di firewall
iptables -I DOCKER-USER -j NFQUEUE --queue-num 0 --queue-bypass

# REGOLE APPLICATE A TUTTO IL TRAFFICO DI RETE VERSO LA GAME_VM --> NON NECESSARIE se I SERVIZI SONO DEI CONTAINER DOCKER
iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass
iptables -I INPUT -j NFQUEUE --queue-num 0 --queue-bypass
iptables -I OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass
```

3. Modificare il `suricata.service` per avviarlo — in automatico in modalità IPS — da rusicata **quando si crea un nuovo servizio**

```bash
sudo nano /usr/lib/systemd/system/suricata.service
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 0 -D # modalità IPS

# N.B.: controllare il path del binario di suricata (se non dovesse essere in /usr/bin)

sudo systemctl daemon-reload
sudo systemctl enable suricata
sudo systemctl start suricata
```

4. Avvia **rusicata** (frontend per suricata) e creare un **servizio per ogni challenge**

```bash
cd rusicata
python3 [manage.py](http://manage.py) migrate
python3 [manage.py](http://manage.py) runserver 0.0.0.0:8000 # o UN'ALTRA PORTA LIBERA
http://IP_VM:8000/admin #inserisci username e password
```

Le regole create con rusicata si trovano in `/var/lib/suricata/rules/`
Per vedere i log in real-time si può consultare il file `fast.log`