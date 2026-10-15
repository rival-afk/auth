#!/usr/bin/env bash
# rotate-keys.sh — ротация инфраструктурных SSH-ключей rival-afk
#
# Роли:
#   provisioner — ключ, которым auth-сервис заходит на phone/pc как root
#   console     — ключ, которым auth-сервис заходит в mind-jail на pc (user mind)
#   tunnel      — ключ обратных туннелей phone/pc -> vps (НЕ ротируется автоматически:
#                 приватный ключ лежит на устройствах, ротация рвёт доступ к phone/pc)
#
# Использование:
#   ./rotate-keys.sh status
#   ./rotate-keys.sh distribute
#   ./rotate-keys.sh rotate <provisioner|console>
#   ./rotate-keys.sh rotate-all
#
# Безопасность: новый ключ сначала рассылается, потом активируется, потом проверяется;
# при неудаче — автоматический откат. Старый provisioner-ключ по умолчанию
# СОХРАНЯЕТСЯ как fallback (KEEP_OLD_PROVISIONER=1). Убрать:
#   KEEP_OLD_PROVISIONER=0 ./rotate-keys.sh rotate provisioner
set -euo pipefail

VPS_SSH_OPTS=(-i "$HOME/.ssh/zenoku-vps" -o StrictHostKeyChecking=no -o ConnectTimeout=12)
VPS_HOST="root@46.183.21.121"
RIVAL_DIR="/etc/rival"
JAIL_AK="/opt/mindjail/home/mind/.ssh/authorized_keys"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$RIVAL_DIR/backup-$STAMP"
KEEP_OLD_PROVISIONER="${KEEP_OLD_PROVISIONER:-1}"
PHONE_USER="u0_a165"

# роль -> файл ключа в /etc/rival (важно: console/tunnel имеют суффикс _key)
keyfile() {
  case "$1" in
    provisioner) echo "$RIVAL_DIR/provisioner" ;;
    console)     echo "$RIVAL_DIR/console_key" ;;
    tunnel)      echo "$RIVAL_DIR/tunnel_key" ;;
    *)           echo "$RIVAL_DIR/$1" ;;
  esac
}

vps()   { ssh "${VPS_SSH_OPTS[@]}" "$VPS_HOST" "$@"; }
phone() { local q; q=$(printf '%q' "$1"); vps "ssh -o BatchMode=yes -o ConnectTimeout=8 -p 8022 -i $RIVAL_DIR/provisioner $PHONE_USER@127.0.0.1 $q"; }
pc()    { local q; q=$(printf '%q' "$1"); vps "ssh -o BatchMode=yes -o ConnectTimeout=8 -p 2222 -i $RIVAL_DIR/provisioner root@127.0.0.1 $q"; }

get_vps_pub() { local kf; kf=$(keyfile "$1"); vps "cat $kf.pub 2>/dev/null" 2>/dev/null || true; }

# добавить pubkey на устройство (без дублей)
add_pub() {
  local dev=$1 pub=$2 comment=$3 rc=0
  case "$dev" in
    vps)   vps "grep -qF '$comment' /root/.ssh/authorized_keys 2>/dev/null || echo '$pub' >> /root/.ssh/authorized_keys" >/dev/null 2>&1 || rc=1 ;;
    phone) phone "grep -qF '$comment' ~/.ssh/authorized_keys 2>/dev/null || echo '$pub' >> ~/.ssh/authorized_keys" >/dev/null 2>&1 || rc=1 ;;
    pc)    pc "grep -qF '$comment' /root/.ssh/authorized_keys 2>/dev/null || echo '$pub' >> /root/.ssh/authorized_keys" >/dev/null 2>&1 || rc=1 ;;
    jail)  pc "D=/opt/mindjail/home/mind/.ssh; mkdir -p \$D; touch \$D/authorized_keys; grep -qF '$comment' \$D/authorized_keys || echo '$pub' >> \$D/authorized_keys; chown -R mind:mind \$D; chmod 700 \$D; chmod 600 \$D/authorized_keys" >/dev/null 2>&1 || rc=1 ;;
  esac
  if [ $rc = 0 ]; then echo "  + $dev: $comment"; else echo "  ! $dev: не удалось добавить $comment"; fi
}

# удалить pubkey с устройства по комментарию
del_pub() {
  local dev=$1 comment=$2 rc=0
  [ -z "$comment" ] && return 0
  case "$dev" in
    vps)   vps "sed -i '/$comment/d' /root/.ssh/authorized_keys 2>/dev/null || true" >/dev/null 2>&1 || rc=1 ;;
    phone) phone "sed -i '/$comment/d' ~/.ssh/authorized_keys 2>/dev/null || true" >/dev/null 2>&1 || rc=1 ;;
    pc)    pc "sed -i '/$comment/d' /root/.ssh/authorized_keys 2>/dev/null || true" >/dev/null 2>&1 || rc=1 ;;
    jail)  pc "sed -i '/$comment/d' $JAIL_AK 2>/dev/null || true" >/dev/null 2>&1 || rc=1 ;;
  esac
  if [ $rc = 0 ]; then echo "  - $dev: $comment"; else echo "  ! $dev: не удалось удалить $comment"; fi
}

# устройства, где авторизован ключ роли
targets_for() {
  case "$1" in
    provisioner) echo "vps phone pc" ;;
    console)     echo "jail" ;;
  esac
}

cmd_status() {
  echo "=== /etc/rival/*.pub на VPS ==="
  vps 'for f in /etc/rival/*.pub; do echo "-- $f"; cat "$f"; done'
  echo
  echo "=== VPS /root/.ssh/authorized_keys (комментарии) ==="
  vps 'awk "{print \$NF}" /root/.ssh/authorized_keys'
  echo
  echo "=== phone authorized_keys ==="
  phone 'cat ~/.ssh/authorized_keys' 2>/dev/null | awk '{print $NF}' || echo "(недоступен)"
  echo
  echo "=== pc authorized_keys (root) ==="
  pc 'cat /root/.ssh/authorized_keys' 2>/dev/null | awk '{print $NF}' || echo "(недоступен)"
  echo
  echo "=== pc mind-jail authorized_keys ==="
  pc "cat $JAIL_AK" 2>/dev/null | awk '{print $NF}' || echo "(недоступен)"
  echo
  echo "=== Termux keys ==="
  for f in "$HOME"/.ssh/*.pub; do echo "-- $f"; cat "$f"; done
}

cmd_distribute() {
  echo "Разношу текущие pubkey на устройства..."
  local pubs=() pub
  for f in "$HOME"/.ssh/zenoku-vps.pub "$HOME"/.ssh/rival.pub; do
    [ -f "$f" ] && pubs+=("$(cat "$f")")
  done
  for role in provisioner tunnel console; do
    pub=$(get_vps_pub "$role")
    [ -n "$pub" ] && pubs+=("$pub")
  done
  for pub in "${pubs[@]}"; do
    local comment; comment=$(echo "$pub" | awk '{print $NF}')
    for dev in vps phone pc; do add_pub "$dev" "$pub" "$comment"; done
  done
}

cmd_rotate() {
  local role=${1:?укажите роль: provisioner|console}
  case "$role" in provisioner|console) ;; *) echo "роль '$role' не ротируется (доступно: provisioner|console)"; return 1 ;; esac
  local kf; kf=$(keyfile "$role")
  local kbase; kbase=$(basename "$kf")
  echo "== Ротация ключа: $role ($kf) =="

  # 1. бэкап старого ключа
  vps "mkdir -p $BACKUP_DIR && cp -f $kf $BACKUP_DIR/ 2>/dev/null; cp -f $kf.pub $BACKUP_DIR/ 2>/dev/null; chmod 600 $BACKUP_DIR/* 2>/dev/null; true"
  local old_pub old_comment
  old_pub=$(vps "cat $kf.pub 2>/dev/null" || true)
  old_comment=$(echo "$old_pub" | awk '{print $NF}')
  echo "  старый: ${old_comment:-?}   (бэкап: $BACKUP_DIR)"

  # 2. новый ключ во временный файл (старый пока рабочий)
  vps "ssh-keygen -t ed25519 -N '' -C '${role}@vps-rot-$STAMP' -f $kf.new -q && chmod 600 $kf.new"
  local new_pub new_comment
  new_pub=$(vps "cat $kf.new.pub")
  new_comment=$(echo "$new_pub" | awk '{print $NF}')
  echo "  новый:  $new_comment"

  # 3. разослать новый pubkey (старый ключ ещё активен)
  echo "3. Добавляю новый ключ на устройства..."
  for dev in $(targets_for "$role"); do add_pub "$dev" "$new_pub" "$new_comment"; done

  # 4. активировать новый ключ
  echo "4. Активирую новый ключ..."
  vps "mv -f $kf.new $kf && mv -f $kf.new.pub $kf.pub"

  # 5. проверка нового ключа
  echo "5. Проверяю новый ключ..."
  local ok=0 out
  case "$role" in
    provisioner)
      out=$(vps "ssh -o BatchMode=yes -o ConnectTimeout=8 -p 8022 -i $kf $PHONE_USER@127.0.0.1 'echo phone_ok'" 2>&1 || true)
      echo "$out" | grep -q phone_ok && echo "  phone: ok" || { echo "  phone: FAIL — $(echo "$out" | tail -1)"; ok=1; }
      out=$(vps "ssh -o BatchMode=yes -o ConnectTimeout=8 -p 2222 -i $kf root@127.0.0.1 'echo pc_ok'" 2>&1 || true)
      echo "$out" | grep -q pc_ok && echo "  pc: ok" || { echo "  pc: FAIL — $(echo "$out" | tail -1)"; ok=1; }
      ;;
    console)
      out=$(vps "ssh -o BatchMode=yes -o ConnectTimeout=8 -i $kf mind@10.66.0.2 'echo jail_ok'" 2>&1 || true)
      echo "$out" | grep -q jail_ok && echo "  jail: ok" || { echo "  jail: FAIL — $(echo "$out" | tail -1)"; ok=1; }
      ;;
  esac

  # откат при неудаче
  if [ "$ok" != 0 ]; then
    echo "!! Проверка не прошла — откатываюсь."
    vps "cp -f $BACKUP_DIR/$kbase $kf && cp -f $BACKUP_DIR/$kbase.pub $kf.pub"
    for dev in $(targets_for "$role"); do del_pub "$dev" "$new_comment"; done
    return 1
  fi

  # 6. убрать старый ключ (кроме provisioner-fallback)
  echo "6. Убираю старый ключ..."
  if [ "$role" = "provisioner" ] && [ "$KEEP_OLD_PROVISIONER" = "1" ]; then
    echo "  provisioner: старый ключ (${old_comment:-?}) ОСТАВЛЕН как fallback (KEEP_OLD_PROVISIONER=1)"
  else
    for dev in $(targets_for "$role"); do del_pub "$dev" "$old_comment"; done
  fi

  echo "== Готово. Новый ключ: $new_comment (бэкап: $BACKUP_DIR) =="
}

case ${1:-help} in
  status)     cmd_status ;;
  distribute) cmd_distribute ;;
  rotate)     cmd_rotate "${2:-}" ;;
  rotate-all) cmd_rotate console && cmd_rotate provisioner ;;
  *)
    echo "Использование: $0 {status|distribute|rotate <role>|rotate-all}"
    echo "  status            — показать ключи на всех устройствах"
    echo "  distribute        — разослать текущие pubkey на все устройства"
    echo "  rotate <role>     — ротировать ключ роли (provisioner|console)"
    echo "  rotate-all        — ротировать console и provisioner"
    ;;
esac
