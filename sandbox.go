package main

// Песочницы админов: chroot на пк (Alpine minirootfs per-admin, свои пакеты
// через pak = doas-хелпер, который выполняет apk ВНУТРИ rootfs користы).

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// sandboxUser — имя песочницы из kid: zs_<hex10>.
func sandboxUser(kid string) (string, error) {
	hexs := ""
	for _, c := range strings.ToLower(kid) {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			hexs += string(c)
		}
	}
	if len(hexs) < 10 {
		return "", fmt.Errorf("kid has too few hex chars for sandbox name")
	}
	return "zs_" + hexs[:10], nil
}

func shQ1(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// provisionExec — то же ssh-исполнение, что provision(), но с произвольным
// скриптом-строкой.
func (s *Server) provisionExec(hcfg *HostCfg, script string) error {
	args := []string{
		"-i", s.cfg.Provisioner,
		"-p", fmt.Sprintf("%d", hcfg.Port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
		fmt.Sprintf("%s@%s", hcfg.User, hcfg.Addr),
		script,
	}
	out, err := exec.Command("ssh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// provisionAdmin — bootstrap песочницы (idempotent) + ttl-слот ключа ak.
func (s *Server) provisionAdmin(hcfg *HostCfg, user, pubLine, comment string) error {
	if s.cfg.SandboxPrefix == "" {
		s.cfg.SandboxPrefix = "/srv/zsandbox"
	}
	R := s.cfg.SandboxPrefix + "/" + user
	cut := time.Now().Add(-slotTTL).Unix()
	prefix := rtSlotPrefix(comment)
	// prefix уже "rt:<kid>:<host>" — awk-фильтр ищет слот со своими слотами

	dlURL := "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-minirootfs-3.22.1-x86_64.tar.gz"
	ak := R + "/rootfs/home/" + user + "/.ssh/authorized_keys"

	// sshd Match: chroot всех zs_* внутрь /srv/zsandbox/<user> (rootfs).
	matchBlock := "Match User zs_*\n    AuthorizedKeysFile " + s.cfg.SandboxPrefix + "/%u/rootfs/home/%u/.ssh/authorized_keys\n    ChrootDirectory /srv/zsandbox/%u\n    PermitTTY yes\n    X11Forwarding no\n    AllowTcpForwarding no\n    Banner none\n"
	// хост-хелпер: doas->root, но apk гоняет только ВНУТРИ rootfs звонящего.
	helper := `#!/bin/sh
# pak host helper: apk install inside the CALLER'S sandbox rootfs only.
N="${DOAS_USER:-}"
case "$N" in zs_[a-f0-9]*) ;; *) echo "pak: bad user" >&2; exit 9;; esac
R=/srv/zsandbox/"$N"/rootfs
case "$1" in add|update|search) ;; *) echo "pak: only add/update/search" >&2; exit 9;; esac
for a in "$@"; do case "$a" in add|update|search|--no-cache|"-U"|*[!a-zA-Z0-9._:@+=-]*) if [ "$a" != "add" ] && [ "$a" != "update" ] && [ "$a" != "search" ] && [ "$a" != "--no-cache" ] && [ "$a" != "-U" ]; then echo "pak: bad arg '$a'" >&2; exit 9; fi;; esac; done
exec chroot "$R" /sbin/apk "$@"
`
	innerPak := `#!/bin/sh
exec doas /usr/local/sbin/zs-pak "$@"
`
	// Deploy minirootfs: чистая алпайн-корневая ФС, suid сняты.
	var b strings.Builder
	b.WriteString("set -eu\n")
	fmt.Fprintf(&b, "N=%s\nR=%s\nP=$(id -u $N 2>/dev/null || true)\n", shQ1(user), shQ1(R))
	b.WriteString(`if [ -z "$P" ]; then mkdir -p /srv/zsandbox/"$N"/rootfs/home/"$N"; adduser -D -h /srv/zsandbox/"$N"/rootfs/home/"$N" -s /bin/sh "$N" >/dev/null 2>&1 || adduser -D -s /bin/sh "$N"; P=$(id -u $N); fi
G=$(id -g $N)
grep -q "Match User zs_" /etc/ssh/sshd_config 2>/dev/null || cat >> /etc/ssh/sshd_config <<'ZSCONF'
` + matchBlock + `ZSCONF
if [ ! -d "$R/rootfs/bin" ]; then
  mkdir -p "$R" && chmod 755 "$R" && mkdir -p "$R/rootfs"
  Z=/var/tmp/amr.$$
  if command -v curl >/dev/null 2>&1; then curl -fsSL ` + dlURL + ` -o "$Z"; else wget -qO "$Z" ` + dlURL + `; fi
  tar -xzf "$Z" -C "$R/rootfs" && rm -f "$Z"
  find "$R/rootfs" -xdev -perm -6000 -type f -exec chmod 700 {} + 2>/dev/null || true
fi
cp -f /etc/resolv.conf "$R/rootfs/etc/resolv.conf" 2>/dev/null || true
grep -q "^$N:" "$R/rootfs/etc/passwd" 2>/dev/null || echo "$N:x:$P:$G:zsandbox:/home/$N:/bin/sh" >> "$R/rootfs/etc/passwd"
grep -q "^$G:" "$R/rootfs/etc/group" 2>/dev/null || echo "$N:x:$G:" >> "$R/rootfs/etc/group"
mkdir -p "$R/rootfs/home/$N/.ssh" "$R/rootfs/dev" "$R/rootfs/proc" "$R/rootfs/usr/local/bin" "$R/rootfs/usr/local/sbin" "$R/rootfs/etc/doas.d"
chown -R "$P:$G" "$R/rootfs/home/$N"
chmod 700 "$R/rootfs/home/$N/.ssh"
[ -e "$R/rootfs/dev/null" ]    || mknod -m 666 "$R/rootfs/dev/null"    c 1 3 2>/dev/null || true
[ -e "$R/rootfs/dev/random" ]  || mknod -m 666 "$R/rootfs/dev/random"  c 1 8 2>/dev/null || true
[ -e "$R/rootfs/dev/urandom" ] || mknod -m 666 "$R/rootfs/dev/urandom" c 1 9 2>/dev/null || true
if ! command -v doas >/dev/null 2>&1; then apk add -q doas >/dev/null 2>&1 || apk add --no-cache -q doas >/dev/null 2>&1; fi
if [ -x /usr/bin/doas ] || [ -x /bin/doas ]; then
  D=$(command -v doas); cp -f "$D" "$R/rootfs/usr/bin/doas"; chown root:root "$R/rootfs/usr/bin/doas"; chmod 4755 "$R/rootfs/usr/bin/doas"
fi
echo "permit nopass $N as root cmd /usr/local/sbin/zs-pak" > "$R/rootfs/etc/doas.d/zs.conf"
mkdir -p /usr/local/sbin
echo '` + strings.ReplaceAll(helper, "'", `'\''`) + `' > /usr/local/sbin/zs-pak
chmod 755 /usr/local/sbin/zs-pak
cp -f /usr/local/sbin/zs-pak "$R/rootfs/usr/local/sbin/zs-pak"
echo '` + strings.ReplaceAll(innerPak, "'", `'\''`) + `' > "$R/rootfs/usr/local/bin/pak"
chmod 755 "$R/rootfs/usr/local/bin/pak"
touch ` + shQ1(ak) + ` && chmod 600 ` + shQ1(ak) + `
awk -v p='` + prefix + `:' -v c=` + fmt.Sprint(cut) + ` '{ if (index($0, p) > 0) { ts=substr($0, index($0, p)+length(p)); gsub(/[^0-9].*/, "", ts); if (ts+0 < c) next } print }' ` + shQ1(ak) + ` > ` + shQ1(ak) + `.tmp && mv ` + shQ1(ak) + `.tmp ` + shQ1(ak) + ` && chmod 600 ` + shQ1(ak) + `
echo ` + shQ1(pubLine) + ` >> ` + shQ1(ak) + `
chmod 600 ` + shQ1(ak) + ` && chown "$P:$G" ` + shQ1(ak) + `
if command -v sshd >/dev/null 2>&1; then sshd -t >/dev/null 2>&1 && { kill -HUP $(head -1 /var/run/sshd.pid 2>/dev/null) 2>/dev/null || true; }; fi
echo ZS-DONE
`)
	return s.provisionExec(hcfg, b.String())
}
