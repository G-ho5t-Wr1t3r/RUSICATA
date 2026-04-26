#!/bin/bash

'''
Setup per automatizzare il deploy e la run di rusicata.
'''

# COLORI
RED="\e[31m" 
GRN="\e[32m"
YLW="\e[33m"
RST="\e[0m"

# Se un comando fallisce fermo lo script
set -e

apt update && apt upgrade -y
apt install -y micro python3-venv

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

# TODO -> Implementare la parte riguardante la modifica del file settings per impostare i giocatori consentiti

# SETTING DJANGO SUPERUSER
export DJANGO_SUPERUSER_PASSWORD="root"
export DJANGO_SUPERUSER_USERNAME="root"
export DJANGO_SUPERUSER_EMAIL="admin@example.com"
python3 manage.py createsuperuser --no-input

sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata jq -y
suricata --build-info

if find var/lib/suricata/rules; then
    echo -e "${YLW}Eseguo il backup delle regole esistenti in /var/lib/suricata/rules/suricata.rules.old${RST}"
    mv /var/lib/suricata/rules/suricata.rules /var/lib/suricata/rules/suricata.rules.old
else
    echo "Creazione cartella rules"
    mkdir -p /var/lib/suricata/rules
fi
touch /var/lib/suricata/rules/suricata.rules
echo "${YLW}Lancio il test per suricata.yaml${RST}"
echo $(sudo suricata -T -c /etc/suricata/suricata.yaml -v)

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

# TODO Suicata service

sudo systemctl daemon-reload
sudo systemctl enable suricata
sudo systemctl start suricata

# TODO start website