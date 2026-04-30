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
    echo "  -v, --verbose Show all commands output"
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
VERBOSE=false

# Parsing argomenti a riga di comando
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help) usage ;;
        -v|--verbose) VERBOSE=true; PARAM_PASSED=true; shift ;;
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

if [ "$VERBOSE" = true ]; then
    exec 3>&1 4>&2
else
    exec 3>/dev/null 4>/dev/null
fi

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

SETTINGS_FILE=$(find . -name "settings.py" | head -n 1)
sed -i "s/ALLOWED_HOSTS = .*/ALLOWED_HOSTS = ['*']/g" "$SETTINGS_FILE" >&3 2>&4

if [ -n "$P1" ]; then sed -i "s/PLAYER_1 = .*/PLAYER_1 = '$P1'/g" "$SETTINGS_FILE" >&3 2>&4; fi
if [ -n "$P2" ]; then sed -i "s/PLAYER_2 = .*/PLAYER_2 = '$P2'/g" "$SETTINGS_FILE" >&3 2>&4; fi
if [ -n "$P3" ]; then sed -i "s/PLAYER_3 = .*/PLAYER_3 = '$P3'/g" "$SETTINGS_FILE" >&3 2>&4; fi
if [ -n "$P4" ]; then sed -i "s/PLAYER_4 = .*/PLAYER_4 = '$P4'/g" "$SETTINGS_FILE" >&3 2>&4; fi
if [ -n "$P5" ]; then sed -i "s/PLAYER_5 = .*/PLAYER_5 = '$P5'/g" "$SETTINGS_FILE" >&3 2>&4; fi
if [ -n "$P6" ]; then sed -i "s/PLAYER_6 = .*/PLAYER_6 = '$P6'/g" "$SETTINGS_FILE" >&3 2>&4; fi

grep -q "TEAM_ALLOWED_IPS" "$SETTINGS_FILE" || echo "TEAM_ALLOWED_IPS = ['127.0.0.1']" >> "$SETTINGS_FILE"

# SETTING DJANGO SUPERUSER
export DJANGO_SUPERUSER_USERNAME="$DB_USER"
export DJANGO_SUPERUSER_PASSWORD="$DB_PASS"
export DJANGO_SUPERUSER_EMAIL="admin@example.com"

python3 rusicata_master/manage.py makemigrations >&3 2>&4
python3 rusicata_master/manage.py migrate >&3 2>&4
python3 rusicata_master/manage.py createsuperuser --no-input >&3 2>&4

add-apt-repository ppa:oisf/suricata-stable -y >&3 2>&4
apt update >&3 2>&4
apt install suricata jq -y >&3 2>&4
suricata --build-info >&3 2>&4

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
    echo -e "${GRN}>Input ✔${RST}"
else 
    echo -e "${RED}Input ✗${RST}"
fi

if iptables -I OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass >&3 2>&4; then
    echo -e "${GRN}Output ✔${RST}"
else 
    echo -e "${RED}Output ✗${RST}"
fi

sed -i 's|^ExecStart=.*|ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 0 -D|' /usr/lib/systemd/system/suricata.service >&3 2>&4

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
if systemctl start suricata >&3 2>&4; then
    echo "Successfully started daemon!"
else
    echo "Failed to start daemon!"
fi

#nohup python3 rusicata_master/manage.py runserver 0.0.0.0:8000 > /dev/null 2>&1 &
nohup python3 rusicata_master/manage.py runserver 0.0.0.0:8000 > full_logs.txt 2>&1 & # Run server, save logs
echo "Rusicata is up!"