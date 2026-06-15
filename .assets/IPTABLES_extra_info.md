# Configurazione di IPTABLES

Le regole iniettate da `setup.sh` instradano il traffico verso Suricata tramite **NFQUEUE**. La scelta di quali chain configurare non è arbitraria e ha implicazioni importanti.

## Comportamento del DNAT di Docker

Quando un container espone una porta (es. `0.0.0.0:80->1234/tcp`), Docker inserisce automaticamente una regola di **DNAT** nella chain `nat/PREROUTING`. Questo significa che il pacchetto viene rediretto **prima** che qualsiasi chain della tabella `filter` lo veda:

```
Pacchetto in arrivo (dst: host:80)
         │
         ▼
[ nat/PREROUTING ]  ← Docker applica DNAT: dst:80 → container_ip:1234
         │
         ▼
[ filter/FORWARD ]  ← il pacchetto ha già dst port 1234, non 80
     └─ DOCKER-USER
     └─ DOCKER
```

**Conseguenza pratica:** eventuali regole Suricata che matchano sulla porta esposta dall'host (es. 80) non avranno effetto. Bisogna usare la porta **interna** del container (es. 1234).

## DOCKER-USER vs FORWARD/INPUT/OUTPUT

| Configurazione | Traffico catturato |
|---|---|
| Solo `DOCKER-USER` | Tutto il traffico Docker (sottoinsieme di FORWARD) |
| `FORWARD` + `INPUT` + `OUTPUT` | Tutto il traffico della macchina (Docker incluso) |
| Tutte e 4 insieme | Il traffico Docker passa in NFQUEUE **due volte** ⚠️ |

Le due configurazioni sono **mutualmente esclusive**:

- Usare `DOCKER-USER` se si vuole ispezionare **solo** il traffico dei container (più leggero).
- Usare `FORWARD` + `INPUT` + `OUTPUT` se si vuole ispezionare **tutto** il traffico della macchina, Docker compreso.

Non vanno mai usate contemporaneamente.

## Verifica dello stato attuale

```bash
# Controllare le regole attive sulla tabella filter
iptables -L -n --line-numbers

# Verificare il DNAT applicato da Docker
iptables -t nat -L PREROUTING -n --line-numbers

# Rimuovere una regola per numero di linea (es. riga 1 di FORWARD)
iptables -D FORWARD 1
```