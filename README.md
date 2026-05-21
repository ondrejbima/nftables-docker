# nftables + Docker s `forward policy drop`

Firewall pro produkční server s Dockerem a Tailscale. Základní princip: **vše zahazuj, povoluj
jen pakety s přesným markem**. Žádné wildcards, žádné broad DNAT pravidla, žádné hardcoded IP
rozsahy v blocking pravidlech.

---

## Obsah

1. [Marky – základní stavební kameny](#marky)
2. [Architektura hooků a priorit](#architektura)
3. [Cesty paketů – krok za krokem](#cesty-paketů)
4. [Soubory a jejich role](#soubory)
5. [Instalace](#instalace)
6. [Ověření funkčnosti](#ověření)
7. [Jak povolit / změnit provoz](#jak-povolit--změnit-provoz)
8. [Troubleshooting](#troubleshooting)

---

## Marky

Každý paket nese 32bitový mark. Pravidla v policy chainu pak rozhodují čistě podle marku – ne
podle interface, IP adresy nebo portu (kromě nutných výjimek popsaných níže).

| Mark (hex)   | Kdo nastaví                          | Co identifikuje                    |
|--------------|--------------------------------------|------------------------------------|
| `0x00050000` | events skript (do Docker child chainů a `docker-mark-input`) | Veškerý Docker provoz (inbound i egress i kontejner→host) |
| `0x00000400` | Tailscale daemon (`ts-forward` chain) | Provoz přicházející z Tailscale VPN |

**Proč dvě hodnoty (`meta mark` a `ct mark`)?**
- `meta mark` – mark aktuálního paketu; platí jen pro tento paket.
- `ct mark` – mark uložený v conntrack záznamu; přenáší se na všechny pakety stejného spojení
  (včetně odpovědí a related paketů), i když na ně `meta mark set` nikdy neběželo.
- Oba se nastavují najednou. Oba se i kontrolují. Tím je pokryta situace, kdy první paket projde
  chain s mark-injekcí, ale odpovědní pakety ne.

---

## Architektura

### Hooky a jejich priority

```
╔══════════════════════════════════════════════════════════════════════════╗
║  PREROUTING  (NAT, priority -100)                                        ║
║  └─ ip nat / Docker DNAT: přepisuje dst pro publikované porty            ║
║     např. :80 → 172.20.0.x:80                                            ║
╚══════════════════════════════════════════════════════════════════════════╝
                         │
              ┌──────────┴──────────┐
              │ routing decision    │
              │ dst = local? INPUT  │
              │ dst = jiný host?    │
              │         FORWARD     │
              └──────────┬──────────┘
                         │
         ┌───────────────┴────────────────────────────┐
         │                                            │
  INPUT hook                                   FORWARD hook
  ─────────────────────────────────            ──────────────────────────────────────
  priority 0: inet filter / chain input        priority 0: ip docker-bridges / filter-FORWARD
    ├─ ct state established,related accept        └─ vmap @filter-forward-in-jumps
    ├─ iif "lo" accept                                └─ filter-forward-in__br-XXX
    ├─ jump docker-mark-input                             ├─ [0] meta mark set 0x00050000 ← inject
    │    └─ iifname "br-XXX" meta mark set 0x00050000    ├─ [1] ct mark set 0x00050000   ← inject
    │    └─ iifname "br-XXX" ct mark set 0x00050000      └─ Docker's own rules
    ├─ mark 0x00050000 → ip daddr 100.100.188.1 drop
    ├─ tcp dport 22 accept                       priority 0 (pokračování):
    ├─ tcp dport {80,443} accept                   └─ vmap @filter-forward-out-jumps
    └─ ... ostatní port pravidla ...                   └─ filter-forward-out__br-XXX
                                                           ├─ [0] meta mark set 0x00050000 ← inject
                                                           ├─ [1] ct mark set 0x00050000   ← inject
                                                           └─ Docker's own rules

                                               priority 10: inet filter / chain forward  ← náš policy
                                                 ├─ ct state established,related accept
                                                 ├─ oifname "tailscale0" + Docker mark → DROP
                                                 ├─ Tailscale mark (0x00000400) → accept
                                                 ├─ Docker mark (0x00050000) → accept
                                                 └─ counter + log + DROP
         │
  POSTROUTING (NAT, priority 100)
  └─ oifname "eth0" + Docker/Tailscale mark → masquerade
```

### Proč priority 10 pro náš forward chain?

Docker registruje `filter-FORWARD` na `priority 0`. Mark-injekce proběhne v priority 0 (v Docker
child chainu). Náš `chain forward` musí mít **vyšší číslo** (= nižší prioritu, tedy běží až po),
aby marky viděl. `filter + 10` = `0 + 10` = 10. Docker child chain → mark set → naše pravidla.

### Proč inject uvnitř Docker child chainů, ne v nadřazeném chainu?

```nft
# BROKEN – toto je mrtvý kód, nikdy se nevykoná:
iifname vmap @filter-forward-in-jumps meta mark set 0x00050000
```

`vmap` je terminální verdict – je to `jump`, po kterém se provádění **nevrací** do volajícího
chainu. Cokoli za `vmap` je nedosažitelný kód. Proto marky injectujeme **dovnitř** child chainů
(`filter-forward-in__br-XXX` a `filter-forward-out__br-XXX`), kde jsou jako první pravidla.

---

## Cesty paketů

### 1. Inbound z internetu → Docker kontejner (např. HTTP přes Traefik)

```
Internet (1.2.3.4:54321) → eth0 → PREROUTING NAT
  └─ Docker DNAT: dst :80 přepíše na 172.20.0.5:80

Routing decision: dst 172.20.0.5 je za Docker bridge → FORWARD

FORWARD priority 0 (Docker filter-FORWARD):
  vmap @filter-forward-out-jumps[br-3009d48bc4d0]
    → filter-forward-out__br-3009d48bc4d0
        [0] meta mark set 0x00050000  ✓
        [1] ct mark set 0x00050000    ✓

FORWARD priority 10 (náš chain forward):
  ct state established,related? → ne (nové spojení)
  oifname "tailscale0"? → ne (oifname je br-3009d48bc4d0)
  meta mark 0x00050000? → ANO → accept ✓

POSTROUTING: oifname "br-3009d48bc4d0" → žádné masquerade pravidlo (masquerade jen pro eth0)

Paket dorazí do Traefik kontejneru.
```

### 2. Egress z Docker kontejneru → internet

```
Kontejner (172.20.0.5) → br-3009d48bc4d0 → Routing decision: dst 1.1.1.1 → eth0 → FORWARD

FORWARD priority 0 (Docker filter-FORWARD):
  vmap @filter-forward-in-jumps[br-3009d48bc4d0]
    → filter-forward-in__br-3009d48bc4d0
        [0] meta mark set 0x00050000  ✓
        [1] ct mark set 0x00050000    ✓

FORWARD priority 10 (náš chain forward):
  ct state established,related? → ne
  oifname "tailscale0"? → ne (oifname je eth0)
  meta mark 0x00050000? → ANO → accept ✓

POSTROUTING:
  oifname "eth0" + meta mark 0x00050000 → masquerade (src přepíše na 178.104.116.206)

Paket odejde na internet se zdrojovou IP serveru.
```

### 3. Docker kontejner → remote Tailscale uzel (BLOKOVÁNO)

```
Kontejner (172.20.0.5) → pokouší se o 100.100.0.5 (jiný Tailscale uzel)

FORWARD priority 0: filter-forward-in__br-XXX → meta mark set 0x00050000 ✓

FORWARD priority 10 (náš chain forward):
  ct state established,related? → ne
  oifname "tailscale0" + meta mark 0x00050000? → ANO → DROP ✗

Paket zahozen. Kontejner se nedostane na Tailscale síť.
```

### 4. Docker kontejner → Tailscale IP tohoto hostu (BLOKOVÁNO)

```
Kontejner (172.20.0.5) → pokouší se o 100.100.188.1 (Tailscale IP tohoto serveru)

Routing decision: 100.100.188.1 je lokální adresa (přiřazená tailscale0) → INPUT
  (poznámka: tento paket NEdostane Docker mark přes forward child chainy,
   protože forward hook vůbec neproběhne)

INPUT priority 0 (náš chain input):
  ct state established,related? → ne (nové spojení)
  iif "lo"? → ne (iifname je br-3009d48bc4d0)
  jump docker-mark-input:
    iifname "br-3009d48bc4d0" → meta mark set 0x00050000 ✓
    iifname "br-3009d48bc4d0" → ct mark set 0x00050000   ✓
  meta mark 0x00050000 + ip daddr 100.100.188.1? → ANO → DROP ✗

Paket zahozen.
```

### 5. Tailscale provoz → tento host (VPN klient → SSH apod.)

```
Jiný Tailscale uzel → tailscale0 → INPUT

INPUT priority 0 (náš chain input):
  ct state established,related? → pokud reply na existující spojení → accept ✓
  iif "lo"? → ne
  jump docker-mark-input:
    iifname "tailscale0" → žádné pravidlo v docker-mark-input → mark zůstane 0
  meta mark 0x00050000 + ip daddr 100.100.188.1? → mark=0 ≠ 0x00050000 → ne
  tcp dport 22? → ANO → accept ✓  (pokud jde o SSH)
```

### 6. Tailscale provoz přes host (VPN → kontejner nebo internet)

```
Jiný Tailscale uzel → tailscale0 → Routing → FORWARD

FORWARD priority 0 (Tailscale ts-forward chain, priority filter = 0):
  iifname "tailscale0" → meta mark set 0x00000400 ✓

FORWARD priority 10 (náš chain forward):
  ct state established,related? → pokud reply → accept ✓
  oifname "tailscale0" + Docker mark? → ne (Docker mark není nastaven)
  meta mark 0x00000400? → ANO → accept ✓
```

---

## Soubory

### `nftables.conf` → `/etc/nftables.conf`

Hlavní firewall. Načítán `nftables.service` při bootu.

**Důležité části:**
- `chain docker-mark-input` – prázdný chain, dynamicky plněný events skriptem; volán přes `jump`
  z `chain input`; nastavuje Docker mark pro pakety z Docker bridge rozhraní v input cestě.
- `chain input` – policy drop; povoluje established/related, loopback, SSH, web porty, Tailscale
  porty; blokuje Docker→Tailscale IP přes mark.
- `chain forward` – policy drop, priority `filter+10`; blokuje Docker→Tailscale (mark+oifname),
  pak povoluje Tailscale mark a Docker mark; vše ostatní zahazuje s logem.
- `table inet nat / chain postrouting` – masquerade pro Docker a Tailscale na `eth0`.

### `nftables-docker-events.sh` → `/usr/local/bin/nftables-docker-events.sh`

Skript se dvěma funkcemi:

**`inject_docker_child_chains <family>`**
Injectuje `meta mark set 0x00050000` + `ct mark set 0x00050000` jako **první dvě pravidla**
do každého Docker child chainu (`filter-forward-in__*` a `filter-forward-out__*`).
Tyto chainy jsou volány výhradně přes Docker's vmap – jsou přesným identifikátorem Docker provozu
ve forward path. Idempotentní (nekopíruje pravidla pokud již existují).

**`inject_docker_input_marks`**
Flushuje chain `inet filter docker-mark-input` a pro každý aktuální Docker bridge přidá:
```nft
iifname "br-XXX" meta mark set 0x00050000
iifname "br-XXX" ct mark set 0x00050000
```
Tím pokrývá input path (kontejner → lokální adresa hostu), kde Docker child chainy neběží.

**Spouštění:**
1. Po startu service (`sleep 2` dává Dockeru čas) – počáteční injekce do všech existujících chainů.
2. Event loop: `docker events --filter type=network --filter event=create/connect` – automatická
   re-injekce při každém novém Docker networku nebo připojení kontejneru.

### `nftables-docker-events.service` → `/etc/systemd/system/nftables-docker-events.service`

Systemd service. Klíčové vlastnosti:
- `After=docker.service nftables.service` – spouští se až po Dockeru a nftables
- `Requires=docker.service` – pokud Docker spadne, service se zastaví
- `Restart=always`, `RestartSec=5s` – automatický restart

---

## Instalace

```bash
# 1. nftables konfig
sudo cp nftables.conf /etc/nftables.conf

# 2. Events skript
sudo cp nftables-docker-events.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/nftables-docker-events.sh

# 3. Systemd service
sudo cp nftables-docker-events.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nftables-docker-events.service
sudo systemctl enable nftables.service
```

---

## Ověření

```bash
# Všechny tři klíčové services běží
sudo systemctl is-active nftables nftables-docker-events docker

# forward chain: priority 10, policy drop, Docker→Tailscale blok, mark accept
sudo nft list chain inet filter forward

# input chain: jump docker-mark-input, mark-based Tailscale blok
sudo nft list chain inet filter input

# docker-mark-input: obsahuje iifname pravidla pro každý bridge
sudo nft list chain inet filter docker-mark-input

# Docker child chainy: první dvě pravidla jsou mark inject
sudo nft list table ip docker-bridges | grep -A5 'filter-forward-in__'

# Logy events skriptu (počáteční injekce po bootu)
sudo journalctl -u nftables-docker-events.service --since boot | head -20

# Test egress z kontejneru (musí vrátit veřejnou IP serveru)
docker run --rm curlimages/curl:8.8.0 -fsS https://api.ipify.org

# Test inbound (musí vrátit odpověď, ne timeout)
curl -fsS --max-time 5 http://178.104.116.206 || true

# Test bloku Docker→Tailscale IP hostu (musí timeout, ne connection refused)
docker run --rm curlimages/curl:8.8.0 --max-time 5 telnet://100.100.188.1:22 2>&1 || true
```

---

## Jak povolit / změnit provoz

### Otevřít nový port na hostu z internetu

Přidej pravidlo do `chain input` v `nftables.conf`, před závěrečný `log + drop`:

```nft
# Příklad: povolení portu 9090 pro Prometheus ze specifické IP
tcp dport 9090 ip saddr 10.0.0.1 ct state new accept

# Příklad: povolení portu 5432 (PostgreSQL) jen z Tailscale
tcp dport 5432 ip saddr 100.0.0.0/8 ct state new accept
```

Pak:
```bash
sudo nft -f /etc/nftables.conf
sudo systemctl restart nftables-docker-events.service  # re-inject marků
```

### Publikovat nový port z Docker kontejneru

Stačí přidat `ports:` v `docker-compose.yml`. Docker sám přidá DNAT pravidlo do `ip nat/PREROUTING`
a přidá accept pravidlo do svých chainů. Firewall to automaticky povolí – Docker provoz má mark
`0x00050000` a ten je v `chain forward` přijat.

```yaml
ports:
  - "8081:8081"   # Docker to zařídí sám, žádná změna nftables není potřeba
```

### Zakázat Docker kontejnerům přístup na internet (egress)

Ve `chain forward` přidej pravidlo **před** Docker mark accept:

```nft
# Blokovat egress z konkrétní Docker bridge sítě (zjisti oifname: ip link show)
iifname "br-3009d48bc4d0" oifname "eth0" meta mark & 0x00ff0000 == 0x00050000 drop
```

Nebo blokovat všem Docker kontejnerům (pozor – přestane fungovat i Traefik proxy):
```nft
oifname "eth0" meta mark & 0x00ff0000 == 0x00050000 drop
```

### Povolit Docker kontejneru přístup na konkrétní Tailscale IP (výjimka)

Aktuálně je blokován veškerý Docker→Tailscale provoz. Pro výjimku přidej pravidlo **před** blok
ve `chain forward`:

```nft
# Příklad: povolení přístupu z Dockeru na konkrétní Tailscale uzel 100.100.0.5
oifname "tailscale0" ip daddr 100.100.0.5 meta mark & 0x00ff0000 == 0x00050000 accept
```

A do `chain input` přidej výjimku **před** Tailscale IP blok (pro případ že jde o lokální IP):
```nft
meta mark & 0x00ff0000 == 0x00050000 ip daddr 100.100.188.1 tcp dport 8080 accept
```

### Povolit Docker kontejnerům přístup na celý Tailscale (zrušení bloku)

Odstraň nebo zakomentuj z `chain forward`:
```nft
# tyto dva řádky smaž nebo zakomentuj:
oifname "tailscale0" meta mark & 0x00ff0000 == 0x00050000 drop
oifname "tailscale0" ct mark & 0x00ff0000 == 0x00050000 drop
```
A z `chain input` odstraň:
```nft
meta mark & 0x00ff0000 == 0x00050000 ip daddr 100.100.188.1 drop
meta mark & 0x00ff0000 == 0x00050000 ip6 daddr fd7a:115c:a1e0:188::1 drop
```

### Přidat pravidlo trvale vs. dočasně

**Dočasně** (platí do restartu nebo reloadu nftables):
```bash
# Příklad: dočasně povolit port 9999
sudo nft add rule inet filter input tcp dport 9999 ct state new accept
```

**Trvale**: uprav `nftables.conf`, pak `sudo nft -f /etc/nftables.conf && sudo systemctl restart nftables-docker-events.service`.

---

## Troubleshooting

### Po reloadu firewallu přestaly fungovat Docker kontejnery

`flush table inet filter` smaže chain `docker-mark-input`, marky v child chainech zůstanou, ale
input blok přestane fungovat správně. Vždy po reloadu:
```bash
sudo systemctl restart nftables-docker-events.service
```

### Kontejner nemá přístup na internet

```bash
# Zkontroluj, jestli má child chain marky
sudo nft list table ip docker-bridges | grep -A4 'filter-forward-in__br-XXX'

# Pokud chybí, re-inject:
sudo systemctl restart nftables-docker-events.service

# Zkontroluj forward chain (měl by projít Docker mark accept)
sudo nft list chain inet filter forward

# Zkontroluj logy zahozených paketů
sudo journalctl -k | grep nftables-forward-drop | tail -20
```

### Nový Docker network nemá marky

Events skript sleduje `docker events create/connect`. Pokud se spustil před vznikem sítě, re-inject
proběhne automaticky při příštím eventu. Pro okamžitou opravu:
```bash
sudo systemctl restart nftables-docker-events.service
```

### Zjistit, proč je paket zahazován

```bash
# Live log zahozených paketů (forward)
sudo journalctl -kf | grep nftables-forward-drop

# Live log zahozených paketů (input)
sudo journalctl -kf | grep nftables-drop

# Zkontrolovat mark na existujícím spojení
sudo conntrack -L | grep <IP>

# Zobrazit celý ruleset
sudo nft list ruleset
```

### Ověřit, že mark byl nastaven

```bash
# Spusť kontejner a sleduj, jestli conntrack záznam má mark 0x00050000
docker run -d --name test-mark nginx
sudo conntrack -L | grep 172.20   # po přístupu na kontejner
# hledej: mark=327680 (= 0x00050000 decimálně)
docker rm -f test-mark
```
