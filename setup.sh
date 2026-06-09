#!/bin/bash

# Setup per automatizzare il deploy e la run di rusicata.

# COLORI
RED="\e[31m"
GRN="\e[32m"
YLW="\e[33m"
RST="\e[0m"

# Se un comando fallisce fermo lo script
set -e

usage() {
    echo -e "${YLW}Usage: $0 [-p1 IP] ... [-p6 IP] [-u USER] [-p PASS] [-v]${RST}"
    echo "Options:"
    echo "  -h, --help    Show this help message"
    echo "  -a <IP>       Set allowed IP (default: 10.254.0.1)"
    echo "  -u <user>     Django superuser username (default: root)"
    echo "  -p <pass>     Django superuser password (default: root)"
    echo "  -d <debug>     Django debug mode !!! INSECURE KEY !!! (default: False)"
    echo "  -v, --verbose Show all commands output"
    echo ""
    exit 1
}

# Default superuser credentials
DB_USER="root"
DB_PASS="root"
IP_HOST="10.254.0.1"
DEBUG=false

VERBOSE=false

# Parsing argomenti a riga di comando
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help) usage ;;
        -v|--verbose) VERBOSE=true; PARAM_PASSED=true ;;
        -a) IP_HOST="$2"; shift ;;
        -u) DB_USER="$2"; shift ;;
        -p) DB_PASS="$2"; shift ;;
        -d) DEBUG="$2"; shift ;;
        *) echo -e "${RED}Unknown parameter: $1${RST}"; usage ;;
    esac
    shift
done

echo -e "${GRN}Starting with username: $DB_USER, password: $DB_PASS, allowed IP: $IP_HOST${RST}"

if [ "$VERBOSE" = true ]; then
    exec 3>&1 4>&2
else
    exec 3>/dev/null 4>/dev/null
fi

echo "INIZIALIZZAZIONE"

# software-properties-common è necessario per add-apt-repository
apt update >&3 2>&4 && apt upgrade -y >&3 2>&4
apt install -y micro python3-venv software-properties-common >&3 2>&4

cd /opt
if [ -f "rusicata.tar.gz" ]; then
    tar xzf rusicata.tar.gz >&3 2>&4
    rm rusicata.tar.gz >&3 2>&4
fi

cd rusicata

# Creazione ambiente virtuale
python3 -m venv .env >&3 2>&4

# Attivazione e VERIFICA
source .env/bin/activate

# Controllo: siamo davvero dentro il venv?
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo -e "${RED}ERRORE: Ambiente virtuale non attivato. Il sistema potrebbe bloccare pip.${RST}"
    exit 1
fi

echo "Installazione dipendenze..."
if pip install -r requirements.txt >&3 2>&4; then
    echo -e "${GRN}Installazione completata con successo nel venv.${RST}"
else
    EXIT_CODE=$?
    echo -e "${RED}Errore durante pip install (Codice: $EXIT_CODE).${RST}"

    if pip install -r requirements.txt --break-system-packages >&3 2>&4; then
        echo -e "${GRN}Installazione FORZATA completata con successo nel venv.${RST}"
    else
        EXIT_CODE=$?
        echo -e "${RED}Errore durante pip installFORZATO (Codice: $EXIT_CODE).${RST}"
        exit 1
    fi
fi

if [ "$DEBUG" = true ]; then
    sed -i "s/DEBUG = .*/DEBUG = True/g" "$SETTINGS_FILE" >&3 2>&4
fi

SETTINGS_FILE=$(find . -name "settings.py" | head -n 1)
sed -i "s/ALLOWED_HOSTS = .*/ALLOWED_HOSTS = ['*']/g" "$SETTINGS_FILE" >&3 2>&4

grep -q "TEAM_ALLOWED_IPS" "$SETTINGS_FILE" || echo "TEAM_ALLOWED_IPS = ['127.0.0.1, $IP_HOST, 10.60.253.253']" >> "$SETTINGS_FILE"

rm rusicata_master/db.sqlite3 || true

# SETTING DJANGO SUPERUSER
export DJANGO_SUPERUSER_USERNAME="$DB_USER"
export DJANGO_SUPERUSER_PASSWORD="$DB_PASS"
export DJANGO_SUPERUSER_EMAIL="admin@example.com"

python3 rusicata_master/manage.py makemigrations >&3 2>&4
python3 rusicata_master/manage.py migrate >&3 2>&4
python3 rusicata_master/manage.py createsuperuser --no-input >&3 2>&4

if ! command -v suricata >/dev/null 2>&1; then
    # Remove broken PPA traces
    rm -f /etc/apt/sources.list.d/*oisf*.list >&3 2>&4 || true
    rm -f /etc/apt/sources.list.d/*suricata*.list >&3 2>&4 || true
    
    apt update >&3 2>&4
    apt install suricata jq -y >&3 2>&4
    #apt install suricata=7.* jq -y >&3 2>&4 || echo "Errore nell'installazione di Suricata 7"
    suricata --build-info >&3 2>&4
else
    echo "Suricata è già presente!"
fi

if find var/lib/suricata/rules > /dev/null 2>&1; then
    echo -e "${YLW}Eseguo il backup delle regole esistenti in /var/lib/suricata/rules/suricata.rules.old${RST}"
    mv /var/lib/suricata/rules/suricata.rules /var/lib/suricata/rules/suricata.rules.old >&3 2>&4
else
    echo "Creazione cartella rules"
    mkdir -p /var/lib/suricata/rules >&3 2>&4
fi
touch /var/lib/suricata/rules/suricata.rules >&3 2>&4

cp rusicata_master/suricata.yaml /etc/suricata/suricata.yaml >&3 2>&4 || true

echo -e "${YLW}Lancio il test per suricata.yaml${RST}"
suricata -T -c /etc/suricata/suricata.yaml -v >&3 2>&4

echo "Imposto i parametri di IPTABLES..."
if iptables -I DOCKER-USER -j NFQUEUE --queue-num 0 --queue-bypass >&3 2>&4; then
    echo -e "${GRN}Docker ✔${RST}"
else
    echo -e "${RED}Docker ✗${RST}"
fi

if iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass >&3 2>&4; then
    echo -e "${GRN}Forward ✔${RST}"
else
    echo -e "${RED}Forward ✗${RST}"
fi

if iptables -I INPUT -j NFQUEUE --queue-num 0 --queue-bypass >&3 2>&4; then
    echo -e "${GRN}Input ✔${RST}"
else
    echo -e "${RED}Input ✗${RST}"
fi

if iptables -I OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass >&3 2>&4; then
    echo -e "${GRN}Output ✔${RST}"
else
    echo -e "${RED}Output ✗${RST}"
fi

sed -i 's|^ExecStart=.*|ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 0 -D|' /usr/lib/systemd/system/suricata.service >&3 2>&4
#sed -i 's/^[[:space:]]*- suricata.rules/  - "*.rules"/' /etc/suricata/suricata.yaml

if grep -A 1 "rule-files:" /etc/suricata/suricata.yaml >&3 2>&4; then
    echo "Successfully modified suricata.yaml"
else
    echo "Generic error while modifying the file!"
fi

if systemctl stop suricata >&3 2>&4; then
    echo "Successfully stopped daemon!"
else
    echo "Failed to stop daemon!"
fi
if systemctl daemon-reload >&3 2>&4; then
    echo "Successfully reloaded daemon!"
else
    echo "Failed to reload daemon!"
fi
if systemctl enable suricata >&3 2>&4; then
    echo "Successfully enabled daemon!"
else
    echo "Failed to enable daemon!"
fi
if systemctl restart suricata >&3 2>&4; then
    echo "Successfully started daemon!"
else
    echo "Failed to start daemon!"
fi

#nohup python3 rusicata_master/manage.py runserver 0.0.0.0:8000 > /dev/null 2>&1 &
nohup python3 rusicata_master/manage.py runserver 0.0.0.0:8000 > full_logs.txt 2>&1 & # Run server, save logs
echo "Rusicata is up!"
echo $(ps aux | grep suricata)
echo "Le regole sono in: /var/lib/suricata/rules/NAME.rules"

LOCAL_IP=$(hostname -I | awk '{print $1}')
echo "Admin panel: http://$LOCAL_IP:8000/admin"
echo "Base: http://$LOCAL_IP:8000/"