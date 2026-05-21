#!/bin/bash
# nftables-docker-events.sh
#
# Dva úkoly:
#   1. Po startu: injectuje Docker mark bit (DOCKER_MARK=0x00010000) do existujících child chainů
#      (nahrazuje původní nftables-docker-hook.sh v ExecStartPost)
#   2. Za běhu: sleduje Docker network eventy a injectuje marky do nových chainů
#
# Docker child chainy (filter-forward-in__* / filter-forward-out__*) jsou volány
# výhradně přes Docker's vlastní vmap → jsou přesným identifikátorem Docker provozu.
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
NFT=/usr/sbin/nft

DOCKER_MARK=0x00010000

inject_docker_child_chains() {
    local family="$1"
    local chains
    chains=$("$NFT" list table "$family" docker-bridges 2>/dev/null \
        | awk '/chain filter-forward-(in|out)__/{print $2}') || return 0

    for chain in $chains; do
        local existing
        existing=$("$NFT" -a list chain "$family" docker-bridges "$chain" 2>/dev/null) || continue

        # Odstranit predchozi Docker mark inserty a vlozit aktualni variantu znovu.
        echo "$existing" | awk -v docker_mark="$DOCKER_MARK" '/meta mark set/ && index($0, docker_mark) {print $NF}' | while read -r handle; do
            [[ -n "$handle" ]] || continue
            "$NFT" delete rule "$family" docker-bridges "$chain" handle "$handle" 2>/dev/null || true
        done
        echo "$existing" | awk -v docker_mark="$DOCKER_MARK" '/ct mark set/ && index($0, docker_mark) {print $NF}' | while read -r handle; do
            [[ -n "$handle" ]] || continue
            "$NFT" delete rule "$family" docker-bridges "$chain" handle "$handle" 2>/dev/null || true
        done

        "$NFT" insert rule "$family" docker-bridges "$chain" ct mark set ct mark or "$DOCKER_MARK"
        "$NFT" insert rule "$family" docker-bridges "$chain" meta mark set meta mark or "$DOCKER_MARK"
    done
}

# Naplni chain docker-mark-input v inet filter mark-injekcnimi pravidly
# pro kazdy aktualni Docker bridge. Konzistentni s forward path (insert do child chainu).
inject_docker_input_marks() {
    local bridges

    "$NFT" flush chain inet filter docker-mark-input 2>/dev/null || return 0
    bridges=$("$NFT" list table ip docker-bridges 2>/dev/null \
        | awk '/chain filter-forward-in__/{sub(/.*filter-forward-in__/, ""); print $1}') || return 0

    for bridge in $bridges; do
        "$NFT" add rule inet filter docker-mark-input iifname "$bridge" meta mark set mark or "$DOCKER_MARK" 2>/dev/null || true
        "$NFT" add rule inet filter docker-mark-input iifname "$bridge" ct mark set ct mark or "$DOCKER_MARK" 2>/dev/null || true
    done
}

# 1. Počáteční injekce při startu service.
#    Docker je v tuto chvíli running, ale mohl vytvořit chainy před tímto service.
#    sleep 2 dává Dockeru čas dokončit setup sítí.
echo "nftables-docker-events: initial injection..."
sleep 2
inject_docker_child_chains ip
inject_docker_child_chains ip6
inject_docker_input_marks
echo "nftables-docker-events: initial injection done."

# 2. Průběžný event listener pro nové Docker sítě.
echo "nftables-docker-events: listening for Docker network events..."
docker events \
    --format '{{.Type}} {{.Action}}' \
    --filter 'type=network' \
    --filter 'event=create' \
    --filter 'event=connect' | \
while read -r _type action; do
    echo "nftables-docker-events: network ${action}, re-injecting marks..."
    sleep 1
    inject_docker_child_chains ip
    inject_docker_child_chains ip6
    inject_docker_input_marks
done
