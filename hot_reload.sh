#!/bin/bash

# COLORI
RED="\e[31m"
GRN="\e[32m"
YLW="\e[33m"
RST="\e[0m"

set -e

echo -e "${YLW}Inizio la procedura di aggiornamento di Rusicata...${RST}"

echo "Cerco e stoppo il server Django corrente..."
if pkill -f "manage.py runserver"; then
    echo -e "${GRN}Server Django fermato con successo.${RST}"
else
    echo -e "${YLW}Nessun server Django in esecuzione trovato. Procedo...${RST}"
fi

DB_PATH="/opt/rusicata/rusicata_master/db.sqlite3"
DB_BACKUP="/opt/db.sqlite3.bak"

if [ -f "$DB_PATH" ]; then
    echo "Eseguo il backup del database esistente..."
    cp "$DB_PATH" "$DB_BACKUP"
    echo -e "${GRN}Backup del DB salvato in $DB_BACKUP${RST}"
else
    echo -e "${RED}Attenzione: Nessun database trovato in $DB_PATH!${RST}"
fi

cd /opt
if [ -f "rusicata.tar.gz" ]; then
    echo "Estraggo la nuova versione da rusicata.tar.gz..."
    tar xzf rusicata.tar.gz
else
    echo -e "${RED}ERRORE: rusicata.tar.gz non trovato in /opt! Interrompo l'aggiornamento.${RST}"
    exit 1
fi

if [ -f "$DB_BACKUP" ]; then
    echo "Ripristino il database..."
    cp "$DB_BACKUP" "/opt/rusicata/rusicata_master/db.sqlite3"
fi

cd /opt/rusicata

SETTINGS_FILE=$(find . -name "settings.py" | head -n 1)
sed -i "s/ALLOWED_HOSTS = .*/ALLOWED_HOSTS = ['*']/g" "$SETTINGS_FILE"

echo "Attivo l'ambiente virtuale..."
source .env/bin/activate

echo "Aggiorno eventuali nuove dipendenze..."
pip install -r requirements.txt > /dev/null 2>&1 || pip install -r requirements.txt --break-system-packages > /dev/null 2>&1

echo "Applico le nuove migrazioni al database (se presenti)..."
python3 rusicata_master/manage.py migrate

echo "Riavvio il server Django..."
nohup python3 rusicata_master/manage.py runserver 0.0.0.0:8000 > full_logs.txt 2>&1 &

LOCAL_IP=$(hostname -I | awk '{print $1}')
echo -e "${GRN}Aggiornamento completato con successo! Rusicata è di nuovo online.${RST}"
echo "Base: http://$LOCAL_IP:8000/"