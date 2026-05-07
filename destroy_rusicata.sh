#!/bin/bash

# Reset script for Rusicata environment - Full Purge

# COLORS
RED="\e[31m"
GRN="\e[32m"
YLW="\e[33m"
RST="\e[0m"

set -e

echo -e "${YLW}Inizio procedura di distruzione totale...${RST}"

echo "Arresto del server Django..."
pkill -f "manage.py runserver" || echo "Server Django non in esecuzione."

echo "Rimozione completa di Suricata..."
systemctl stop suricata 2>/dev/null || true
systemctl disable suricata 2>/dev/null || true
apt purge -y suricata > /dev/null 2>&1 || echo "Suricata non trovato."
rm -rf /etc/suricata
rm -rf /var/lib/suricata
rm -rf /var/log/suricata

echo "Rimozione regole NFQUEUE da IPTables..."
iptables -D DOCKER-USER -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
iptables -D FORWARD -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
iptables -D INPUT -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
iptables -D OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true

if [ -d "/opt/rusicata" ]; then
    echo "Pulizia cartella /opt/rusicata..."
    cd /opt/rusicata
    
    rm -rf .env
    echo "Ambiente virtuale rimosso."

    rm -f rusicata_master/db.sqlite3
    echo "Database rimosso."

    rm -f full_logs.txt
else
    echo "Directory /opt/rusicata non trovata."
fi

echo "Pulizia pacchetti residui..."
apt autoremove -y > /dev/null 2>&1
apt autoclean > /dev/null 2>&1

rm -rf /opt/rusicata
rm /opt/rusicata.tar.gz
rm /opt/setup.sh
rm /opt/destroy_rusicata.sh

echo -e "${GRN}Reset completato. Suricata e le configurazioni sono state rimosse.${RST}"