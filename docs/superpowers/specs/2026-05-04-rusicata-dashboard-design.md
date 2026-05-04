# Design Spec: Rusicata Dashboard & Telemetries
**Data:** 2026-05-04
**Stato:** Draft
**Autore:** gianny (via Gemini CLI)

## 1. Obiettivo
Creare una dashboard personalizzata per Rusicata che permetta di gestire le regole di Suricata in modo visuale, monitorare le telemetrie in tempo reale e gestire lo stato dei servizi senza utilizzare esclusivamente l'interfaccia admin di Django. L'applicazione deve rimanere "lightweight" e performante.

## 2. Architettura Tecnica
Il sistema utilizzerà un approccio **Hybrid SSR + JSON API**:
- **Backend:** Django (Python 3.12).
- **Frontend:** Django Templates + Vanilla CSS + Vanilla JS.
- **Librerie Esterne:** Chart.js (via CDN).
- **Dati:** Integrazione con i modelli esistenti e parsing del file `eve.json` di Suricata.

## 3. Modifiche al Modello Dati (`rusicata_manager/models.py`)
### 3.1 Modello `HttpRule`
- Aggiunta campo `is_active = models.BooleanField(default=True)`.
- Modifica dei metodi `insert_rule` e `remove_rule` per rispettare il flag `is_active`.
- Logica di salvataggio: se una regola è disattivata, viene rimossa dal file `.rules` fisico ma conservata nel database.

## 4. Nuove View e Endpoint API
### 4.1 Dashboard Page (`/`)
- Rendering della pagina principale con la lista dei servizi e delle regole.
- Iniezione iniziale dei dati tramite contesto Django.

### 4.2 API Endpoints
- `GET /api/stats/`: Restituisce dati JSON aggregati dai log di Suricata (conteggio alert per tipo/servizio).
- `POST /api/rules/<id>/toggle/`: Attiva/disattiva una regola asincronamente.
- `GET /api/logs/latest/`: Restituisce l'ultimo log ID per il sistema di notifiche "suggest refresh".

## 5. Design dell'Interfaccia (UI)
### 5.1 Layout Rule-Centric
- **Header:** Link rapido all'Admin Django, counter globali di alert.
- **Top Section (Telemetria):**
    - Grafico a Ciambella (Donut) con Chart.js che mostra la distribuzione degli alert/drop.
- **Main Section (Services Grid):**
    - Card espandibili per ogni `Service`.
    - All'espansione: Tabella delle `HttpRule` associate con pulsanti:
        - **Start/Stop:** Toggle immediato tramite API.
        - **Edit:** Link diretto alla pagina di modifica dell'admin.

### 5.2 Notifiche e Reattività
- Un banner Toast apparirà in alto quando viene rilevata nuova attività nei log tramite polling JS leggero (ogni 30 secondi).
- Il banner suggerirà il refresh della pagina: *"Nuovi eventi rilevati. [Aggiorna]"*.

## 6. Parsing dei Log (`eve.json`)
- Implementazione di una funzione di parsing efficiente che legge le ultime N righe di `eve.json`.
- Filtra i log per `alert.signature_id` per correlarli alle regole gestite da Rusicata.

## 7. Sicurezza
- Tutte le nuove view e API richiederanno l'autenticazione (`LoginRequiredMixin`).
- Rimane attivo il `TeamIPWhitelistMiddleware` per l'intero sito.

## 8. Piano di Test
- Verifica attivazione/disattivazione regola nel DB e nel file system.
- Verifica corretto caricamento del grafico con dati reali da `eve.json`.
- Verifica responsività del layout su diverse risoluzioni (Desktop/Tablet).
