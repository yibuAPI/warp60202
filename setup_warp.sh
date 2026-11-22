#!/usr/bin/env bash
# Install + register Cloudflare WARP on a GitHub-hosted Ubuntu runner (uid 1001 + sudo).
# Preferred: official client in PROXY mode -> SOCKS5 on 127.0.0.1:40000 (no TUN needed,
# still gives Cloudflare-native IPv4+IPv6 egress for socks5h clients).
# Fallback: wgcf (already proven to register+generate profile on this runner) + wireguard.
SUDO="sudo -n"
log(){ echo "[warp] $*"; }

echo "===== runner identity ====="
id; uname -a; . /etc/os-release; echo "CODENAME=$VERSION_CODENAME"
$SUDO -v || { echo "NO SUDO"; exit 1; }

install_client() {
  local cn
  for cn in jammy noble "$VERSION_CODENAME"; do
    [ -z "$cn" ] && continue
    log "trying cloudflare-warp repo codename=$cn"
    if curl -fsSL --max-time 30 https://pkg.cloudflareclient.com/pubkey.gpg \
        | $SUDO gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null; then
      echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $cn main" \
        | $SUDO tee /etc/apt/sources.list.d/cloudflare-warp.list >/dev/null
      if $SUDO apt-get -o Dpkg::Options::=--force-confnew update -qq >/dev/null 2>&1; then
        if $SUDO apt-get -o Dpkg::Options::=--force-confnew install -y --no-install-recommends cloudflare-warp >/tmp/warp_apt.log 2>&1; then
          log "installed cloudflare-warp via apt (codename=$cn)"; return 0
        fi
      fi
    fi
  done
  log "apt path failed; downloading .deb directly from package index"
  local idx="https://pkg.cloudflareclient.com/dists/jammy/main/binary-amd64/Packages"
  local fn
  fn=$(curl -fsSL --max-time 40 "$idx" | awk '/^Filename: /{f=$2} /^Package: cloudflare-warp$/{p=1} p&&/^Version: /{v=$2} p&&f{print f; exit}')
  [ -z "$fn" ] && return 1
  log "deb path=$fn"
  curl -fsSL --max-time 180 "https://pkg.cloudflareclient.com/$fn" -o /tmp/warp.deb || return 1
  $SUDO apt-get install -y /tmp/warp.deb >/tmp/warp_deb.log 2>&1 || $SUDO apt-get -f install -y >>/tmp/warp_deb.log 2>&1 || return 1
  command -v warp-cli >/dev/null && return 0
  return 1
}

start_svc() {
  $SUDO systemctl enable --now warp-svc >/dev/null 2>&1 && log "warp-svc via systemd" && return 0
  log "systemd start failed; launching warp-svc manually"
  ($SUDO nohup warp-svc --accept-tos >/var/log/warp-svc.log 2>&1 &) || true
  sleep 5
  pgrep -a warp-svc || true
}

cli(){ $SUDO warp-cli --accept-tos "$@" 2>&1; }

register_connect() {
  local i
  for i in $(seq 1 25); do cli status >/dev/null 2>&1 && break; sleep 1; done
  cli status | head -3
  log "registration"
  cli registration new || cli register || { log "register failed"; return 1; }
  sleep 2
  cli mode proxy || cli set-mode proxy || true
  cli connect || true
  for i in $(seq 1 30); do
    local st; st=$(cli status)
    echo "  status[$i]: $st"
    echo "$st" | grep -qiE 'Connected|已连接' && break
    [ $i -eq 12 ] && { cli connect || true; }
    sleep 2
  done
  cli status
  for i in $(seq 1 20); do
    (echo >/dev/tcp/127.0.0.1/40000) >/dev/null 2>&1 && { log "socks5 127.0.0.1:40000 listening"; return 0; }
    sleep 1
  done
  log "40000 not listening"; return 1
}

verify_egress() {
  local px="$1"
  echo "----- WARP egress identity (px='${px}') -----"
  curl -s -m 30 -x "$px" https://www.cloudflare.com/cdn-cgi/trace 2>&1 | grep -E '^(ip|warp|loc|colo|http)=' || echo "trace FAILED"
  echo "--- ipv4 ---"; curl -s -m 20 -x "$px" https://api.ipify.org 2>&1; echo
  echo "--- ipv6 (AAAA-only host) ---"; curl -s -m 20 -x "$px" https://ipv6.icanhazip.com 2>&1; echo
  echo "--- target http ---"
  curl -s -m 25 -x "$px" -o /dev/null -w "target http /api/status http=%{http_code} t=%{time_total}\n" http://135.148.204.37/api/status || echo "target http FAILED"
  curl -sk -m 25 -x "$px" -o /dev/null -w "target https /api/status http=%{http_code}\n" https://135.148.204.37/api/status || echo "target https FAILED"
  echo "--- challenges.cloudflare.com ---"
  curl -s -m 25 -x "$px" -o /dev/null -w "cf api.js http=%{http_code} size=%{size_download}\n" "https://challenges.cloudflare.com/turnstile/v0/api.js" || echo "cf api.js FAILED"
  echo "--- brunhild (AAAA-only challenge host) ---"
  curl -s -m 25 -x "$px" -o /dev/null -w "brunhild http=%{http_code} (404/403 ok, 000=fail)\n" "https://brunhild.challenges.cloudflare.com/cdn-cgi/challenge-platform/" || echo "brunhild FAILED"
}

METHOD=none
if install_client; then
  start_svc
  if register_connect; then
    if verify_egress socks5h://127.0.0.1:40000; then METHOD=warp-cli-proxy; fi
  fi
fi

if [ "$METHOD" = none ]; then
  log "===== FALLBACK: wgcf + wireguard (tun) ====="
  $SUDO apt-get -o Dpkg::Options::=--force-confnew install -y wireguard-tools resolvconf iproute2 >/dev/null 2>&1 || true
  ARCH=amd64; [ "$(uname -m)" = aarch64 ] && ARCH=arm64
  curl -fsSL -m 120 -o /tmp/wgcf "https://github.com/ViRb3/wgcf/releases/download/v2.2.27/wgcf_2.2.27_linux_${ARCH}" && $SUDO install -m755 /tmp/wgcf /usr/local/bin/wgcf || true
  if command -v wgcf >/dev/null; then
    wgcf register --accept-tos || true
    wgcf generate || true
  fi
  if [ -f wgcf-profile.conf ]; then
    $SUDO modprobe wireguard >/dev/null 2>&1 || true
    $SUDO wg-quick up "$PWD/wgcf-profile.conf" 2>&1 | tail -5 || true
    sleep 3
    echo "--- wg show ---"; $SUDO wg show || true
    if verify_egress ""; then METHOD=wgcf-tunnel; fi
  fi
fi

echo "WARP_METHOD=$METHOD" | tee warp_method.env
[ "$METHOD" = none ] && { echo "WARP_SETUP_FAILED"; tail -40 /tmp/warp_apt.log /tmp/warp_deb.log /var/log/warp-svc.log 2>/dev/null; exit 1; }
echo "WARP_SETUP_OK method=$METHOD"