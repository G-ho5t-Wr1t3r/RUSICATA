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
    echo -e "${YLW}Usage: $0 [-p1 IP] ... [-p6 IP] [-u USER] [-p PASS]${RST}"
    echo "Options:"
    echo "  -h, --help    Show this help message"
    echo "  -p1 <IP>      Set IP for Player 1"
    echo "  -p2 <IP>      Set IP for Player 2"
    echo "  -p3 <IP>      Set IP for Player 3"
    echo "  -p4 <IP>      Set IP for Player 4"
    echo "  -p5 <IP>      Set IP for Player 5"
    echo "  -p6 <IP>      Set IP for Player 6"
    echo "  -u <user>     Django superuser username (default: root)"
    echo "  -p <pass>     Django superuser password (default: root)"
    echo ""
    echo "Provide at least one parameter."
    exit 1
}

# Default superuser credentials
DB_USER="root"
DB_PASS="root"

PARAM_PASSED=false

# Parsing argomenti a riga di comando
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help) usage ;;
        -p1) P1="$2"; PARAM_PASSED=true; shift ;;
        -p2) P2="$2"; PARAM_PASSED=true; shift ;;
        -p3) P3="$2"; PARAM_PASSED=true; shift ;;
        -p4) P4="$2"; PARAM_PASSED=true; shift ;;
        -p5) P5="$2"; PARAM_PASSED=true; shift ;;
        -p6) P6="$2"; PARAM_PASSED=true; shift ;;
        -u) DB_USER="$2"; PARAM_PASSED=true; shift ;;
        -p) DB_PASS="$2"; PARAM_PASSED=true; shift ;;
        *) echo -e "${RED}Unknown parameter: $1${RST}"; usage ;;
    esac
    shift
done

# Verifica che almeno un parametro sia stato passato
if [ "$PARAM_PASSED" = false ]; then
    echo -e "${RED}Error: No parameters provided.${RST}"
    usage
fi

# software-properties-common è necessario per add-apt-repository
apt update && apt upgrade -y
apt install -y micro python3-venv software-properties-common

cd /opt
if [ -f "rusicata.tar.gz" ]; then
    tar xzf rusicata.tar.gz
    rm rusicata.tar.gz
fi

cd rusicata

# Creazione ambiente virtuale
python3 -m venv .env

# Attivazione e VERIFICA
source .env/bin/activate

# Controllo: siamo davvero dentro il venv?
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo -e "${RED}ERRORE: Ambiente virtuale non attivato. Il sistema potrebbe bloccare pip.${RST}"
    exit 1
fi

echo "Installazione dipendenze..."
if pip install -r requirements.txt; then
    echo "${GRN}Installazione completata con successo nel venv.${RST}"
else
    EXIT_CODE=$?
    echo "${RED}Errore durante pip install (Codice: $EXIT_CODE).${RST}"
    
    if pip install -r requirements.txt --break-system-packages; then
        echo "${GRN}Installazione FORZATA completata con successo nel venv.${RST}"
    else
        EXIT_CODE=$?
        echo "${RED}Errore durante pip installFORZATO (Codice: $EXIT_CODE).${RST}"
        exit 1
    fi
fi

SETTINGS_FILE=$(find . -name "settings.py" | head -n 1)
sed -i "s/ALLOWED_HOSTS = .*/ALLOWED_HOSTS = ['*']/g" "$SETTINGS_FILE"

if [ -n "$P1" ]; then sed -i "s/PLAYER_1 = .*/PLAYER_1 = '$P1'/g" "$SETTINGS_FILE"; fi
if [ -n "$P2" ]; then sed -i "s/PLAYER_2 = .*/PLAYER_2 = '$P2'/g" "$SETTINGS_FILE"; fi
if [ -n "$P3" ]; then sed -i "s/PLAYER_3 = .*/PLAYER_3 = '$P3'/g" "$SETTINGS_FILE"; fi
if [ -n "$P4" ]; then sed -i "s/PLAYER_4 = .*/PLAYER_4 = '$P4'/g" "$SETTINGS_FILE"; fi
if [ -n "$P5" ]; then sed -i "s/PLAYER_5 = .*/PLAYER_5 = '$P5'/g" "$SETTINGS_FILE"; fi
if [ -n "$P6" ]; then sed -i "s/PLAYER_6 = .*/PLAYER_6 = '$P6'/g" "$SETTINGS_FILE"; fi

grep -q "TEAM_ALLOWED_IPS" "$SETTINGS_FILE" || echo "TEAM_ALLOWED_IPS = ['127.0.0.1']" >> "$SETTINGS_FILE"

# SETTING DJANGO SUPERUSER
export DJANGO_SUPERUSER_USERNAME="$DB_USER"
export DJANGO_SUPERUSER_PASSWORD="$DB_PASS"
export DJANGO_SUPERUSER_EMAIL="admin@example.com"

python3 rusicata_master/manage.py makemigrations
python3 rusicata_master/manage.py migrate
python3 rusicata_master/manage.py createsuperuser --no-input

add-apt-repository ppa:oisf/suricata-stable -y
apt update
apt install suricata jq -y
suricata --build-info

if find var/lib/suricata/rules > /dev/null 2>&1; then
    echo -e "${YLW}Eseguo il backup delle regole esistenti in /var/lib/suricata/rules/suricata.rules.old${RST}"
    mv /var/lib/suricata/rules/suricata.rules /var/lib/suricata/rules/suricata.rules.old
else
    echo "Creazione cartella rules"
    mkdir -p /var/lib/suricata/rules
fi
touch /var/lib/suricata/rules/suricata.rules

cp rusicata_master/suricata.yaml /etc/suricata/suricata.yaml || true

echo "${YLW}Lancio il test per suricata.yaml${RST}"
suricata -T -c /etc/suricata/suricata.yaml -v

echo "Imposto i parametri di IPTABLES..."
if iptables -I DOCKER-USER -j NFQUEUE --queue-num 0 --queue-bypass; then
    echo "${GRN}Docker ✔${RST}"
else 
    echo "${RED}Docker ✗${RST}"
fi

if iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass; then
    echo "${GRN}Forward ✔${RST}"
else 
    echo "${RED}Forward ✗${RST}"
fi

if iptables -I INPUT -j NFQUEUE --queue-num 0 --queue-bypass; then
    echo "${GRN}>Input ✔${RST}"
else 
    echo "${RED}Input ✗${RST}"
fi

if iptables -I OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass; then
    echo "${GRN}Output ✔${RST}"
else 
    echo "${RED}Output ✗${RST}"
fi

sed -i 's|^ExecStart=.*|ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 0 -D|' /usr/lib/systemd/system/suricata.service

if systemctl daemon-reload; then
	echo "Successfully reloaded daemon!"
else
	echo "Failed to reload daemon!"
fi
if systemctl enable suricata; then
	echo "Successfully enabled daemon!"
else
	echo "Failed to enable daemon!"
fi
if systemctl start suricata; then
	echo "Successfully started daemon!"
else
	echo "Failed to start daemon!"
fi

#nohup python3 rusicata_master/manage.py runserver 0.0.0.0:8000 > /dev/null 2>&1 &
nohup python3 rusicata_master/manage.py runserver 0.0.0.0:8000 > full_logs.txt 2>&1 & # Run server, save logs
echo "Rusicata is up!"
