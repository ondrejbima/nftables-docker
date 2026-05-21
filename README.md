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
| `0x00010000` | events skript (do Docker child chainů a `docker-mark-input`) | Boolean-like flag `is_docker` pro veškerý Docker provoz |
| `0x00000400` | Tailscale daemon (`ts-forward` chain) | Boolean-like flag `is_tailscale` pro provoz z Tailscale VPN |

V `nftables.conf` jsou tyto bity pojmenované přes:
```nft
define is_docker = 0x00010000
define is_tailscale = 0x00000400
```

Pravidla se pak dají číst jako:
```nft
oifname "tailscale0" meta mark & $is_docker == $is_docker drop
```

Poznámka: `nft list ruleset` vypisuje live ruleset už s expandovanými hodnotami, takže v běžícím
výpisu uvidíš zase `0x00010000`, ne název `$is_docker`.

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
    ├─ jump docker-mark-input                             ├─ [0] meta mark set meta mark | 0x00010000 ← inject
    │    └─ iifname "br-XXX" meta mark set meta mark | 0x00010000    ├─ [1] ct mark set ct mark | 0x00010000   ← inject
    │    └─ iifname "br-XXX" ct mark set ct mark | 0x00010000        └─ Docker's own rules
    ├─ mark 0x00010000 → ip daddr 100.100.188.1 drop
    ├─ iifname "eth0" → jump internet-services    priority 0 (pokračování):
    │    ├─ ct original proto-dst 22 accept         └─ vmap @filter-forward-out-jumps
    │    ├─ ct original proto-dst {80,443} accept       └─ filter-forward-out__br-XXX
    │    └─ meta l4proto {tcp,udp} log+drop             ├─ [0] meta mark set meta mark | 0x00010000 ← inject
    └─ tcp dport 22 accept (privátní vstup)             ├─ [1] ct mark set ct mark | 0x00010000   ← inject
                                                           ├─ [0] meta mark set meta mark | 0x00010000 ← inject
                                                           ├─ [1] ct mark set ct mark | 0x00010000   ← inject
                                                           └─ Docker's own rules

                                               priority 10: inet filter / chain forward  ← náš policy
                                                 ├─ ct state established,related accept
                                                 ├─ iifname "eth0" → jump internet-services
                                                 ├─ oifname "tailscale0" + Docker mark → log + DROP
                                                 ├─ Tailscale mark (0x00000400) → accept
                                                 ├─ Docker mark (0x00010000) → accept
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
iifname vmap @filter-forward-in-jumps meta mark set meta mark | 0x00010000
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
        [0] meta mark set meta mark | 0x00010000  ✓
        [1] ct mark set ct mark | 0x00010000      ✓

FORWARD priority 10 (náš chain forward):
  ct state established,related? → ne (nové spojení)
  oifname "tailscale0"? → ne (oifname je br-3009d48bc4d0)
  meta mark 0x00010000? → ANO → accept ✓

POSTROUTING: oifname "br-3009d48bc4d0" → žádné masquerade pravidlo (masquerade jen pro eth0)

Paket dorazí do Traefik kontejneru.
```

### 2. Egress z Docker kontejneru → internet

```
Kontejner (172.20.0.5) → br-3009d48bc4d0 → Routing decision: dst 1.1.1.1 → eth0 → FORWARD

FORWARD priority 0 (Docker filter-FORWARD):
  vmap @filter-forward-in-jumps[br-3009d48bc4d0]
    → filter-forward-in__br-3009d48bc4d0
        [0] meta mark set meta mark | 0x00010000  ✓
        [1] ct mark set ct mark | 0x00010000      ✓

FORWARD priority 10 (náš chain forward):
  ct state established,related? → ne
  oifname "tailscale0"? → ne (oifname je eth0)
  meta mark 0x00010000? → ANO → accept ✓

POSTROUTING:
  oifname "eth0" + meta mark 0x00010000 → masquerade (src přepíše na 178.104.116.206)

Paket odejde na internet se zdrojovou IP serveru.
```

### 3. Docker kontejner → remote Tailscale uzel (BLOKOVÁNO)

```
Kontejner (172.20.0.5) → pokouší se o 100.100.0.5 (jiný Tailscale uzel)

FORWARD priority 0: filter-forward-in__br-XXX → meta mark set meta mark | 0x00010000 ✓

FORWARD priority 10 (náš chain forward):
  ct state established,related? → ne
  oifname "tailscale0" + meta mark 0x00010000? → ANO → DROP ✗

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
    iifname "br-3009d48bc4d0" → meta mark set meta mark | 0x00010000 ✓
    iifname "br-3009d48bc4d0" → ct mark set ct mark | 0x00010000     ✓
  meta mark 0x00010000 + ip daddr 100.100.188.1? → ANO → DROP ✗

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
  meta mark 0x00010000 + ip daddr 100.100.188.1? → mark=0 ≠ 0x00010000 → ne
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
- `chain internet-services` – centrální allowlist pro veřejné služby; používá
  `ct original proto-dst`, takže jedno pravidlo funguje stejně pro host službu i Docker published
  port po DNAT.
- `chain docker-to-tailscale` – sdílený blok pro Docker→Tailscale; je volán z `chain input` i
  `chain forward` a drží všechna pravidla na jednom místě.
- `chain input` – policy drop; povoluje established/related a loopback; Docker pakety po
  `docker-mark-input` posílá do `chain docker-to-tailscale`, pak nové veřejné spojení z `eth0`
  do `chain internet-services`.
- `chain forward` – policy drop, priority `filter+10`; nejdřív volá `chain docker-to-tailscale`,
  pak nové veřejné spojení z `eth0` posílá do `chain internet-services`; zbytek řeší Tailscale a
  Docker mark accept pravidla.
- `table inet nat / chain postrouting` – masquerade pro Docker a Tailscale na `eth0`.

### `nftables-docker-events.sh` → `/usr/local/bin/nftables-docker-events.sh`

Skript se dvěma funkcemi:

**`inject_docker_child_chains <family>`**
Injectuje `meta mark set meta mark | 0x00010000` + `ct mark set ct mark | 0x00010000` jako
**první dvě pravidla**
do každého Docker child chainu (`filter-forward-in__*` a `filter-forward-out__*`).
Tyto chainy jsou volány výhradně přes Docker's vmap – jsou přesným identifikátorem Docker provozu
ve forward path. Při startu nejprve odstraní své předchozí inserty s aktuálním Docker bitem a vloží je znovu.

**`inject_docker_input_marks`**
Flushuje chain `inet filter docker-mark-input` a pro každý aktuální Docker bridge přidá:
```nft
iifname "br-XXX" meta mark set meta mark | 0x00010000
iifname "br-XXX" ct mark set ct mark | 0x00010000
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

# internet-services: centrální allowlist veřejných portů
sudo nft list chain inet filter internet-services

# forward chain: priority 10, policy drop, Docker→Tailscale blok, mark accept
sudo nft list chain inet filter forward

# docker-to-tailscale: sdílený blok pro input i forward
sudo nft list chain inet filter docker-to-tailscale

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

### Povolit novou veřejnou službu (host i Docker)

Veřejné porty se řídí v jediném místě: `chain internet-services`.
Používá `ct original proto-dst`, takže stejné pravidlo funguje pro:
- nativní službu na hostu
- Docker published port po DNAT

Pravidla přidávej před závěrečný `meta l4proto { tcp, udp } log ... drop`:

```nft
# TCP port otevřený všem
meta l4proto tcp ct original proto-dst 8080 accept

# TCP port jen z jedné veřejné IP
ip saddr 203.0.113.10 meta l4proto tcp ct original proto-dst 8080 accept

# TCP port jen z více veřejných IP
ip saddr { 203.0.113.10, 198.51.100.25 } meta l4proto tcp ct original proto-dst 8443 accept

# UDP port otevřený všem
meta l4proto udp ct original proto-dst 3478 accept
```

Pak:
```bash
sudo nft -f /etc/nftables.conf
sudo systemctl restart nftables-docker-events.service  # re-inject marků
```

### Publikovat nový port z Docker kontejneru

Potřebuješ dva kroky:
1. Publikovat port v `docker-compose.yml`.
2. Přidat odpovídající pravidlo do `chain internet-services`.

```yaml
ports:
  - "8081:8081"
```

```nft
# Varianta A: port 8081 otevřený všem
meta l4proto tcp ct original proto-dst 8081 accept

# Varianta B: port 8081 jen z jedné veřejné IP
ip saddr 1.2.3.4 meta l4proto tcp ct original proto-dst 8081 accept
```

### Zakázat Docker kontejnerům přístup na internet (egress)

Ve `chain forward` přidej pravidlo **před** Docker mark accept:

```nft
# Blokovat egress z konkrétní Docker bridge sítě (zjisti oifname: ip link show)
iifname "br-3009d48bc4d0" oifname "eth0" meta mark & $is_docker == $is_docker drop
```

Nebo blokovat všem Docker kontejnerům (pozor – přestane fungovat i Traefik proxy):
```nft
oifname "eth0" meta mark & $is_docker == $is_docker drop
```

### Povolit Docker kontejneru přístup na konkrétní Tailscale IP (výjimka)

Aktuálně je blokován veškerý Docker→Tailscale provoz. Pro výjimku přidej pravidlo **před** blok
do `chain docker-to-tailscale`:

```nft
# Příklad: povolení přístupu z Dockeru na konkrétní Tailscale uzel 100.100.0.5
meta mark & $is_docker == $is_docker ip daddr 100.100.0.5 accept
```

Pokud jde o lokální Tailscale IP tohoto hostu, stejný chain už pokrývá i `input` cestu; výjimku
přidej tam stejným stylem, jen podle cílové adresy.

### Povolit Docker kontejnerům přístup na celý Tailscale (zrušení bloku)

Odstraň nebo zakomentuj odpovídající řádky z `chain docker-to-tailscale`.

### Přidat pravidlo trvale vs. dočasně

**Dočasně** (platí do restartu nebo reloadu nftables):
```bash
# Příklad: dočasně povolit port 9999 v centrálním allowlistu
# Použij insert, protože na konci chainu je log+drop.
sudo nft insert rule inet filter internet-services meta l4proto tcp ct original proto-dst 9999 accept
```

**Trvale**: uprav `chain internet-services` v `nftables.conf`, pak `sudo nft -f /etc/nftables.conf && sudo systemctl restart nftables-docker-events.service`.

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
# Spusť kontejner a sleduj, jestli conntrack záznam má mark 0x00010000
docker run -d --name test-mark nginx
sudo conntrack -L | grep 172.20   # po přístupu na kontejner
# hledej: mark=65536 (= 0x00010000 decimálně)
docker rm -f test-mark
```
