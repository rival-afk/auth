package main

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/ssh"
	_ "modernc.org/sqlite"
)

type HostCfg struct {
	Addr   string `json:"addr"`
	Port   int    `json:"port"`
	User   string `json:"user"`
	Local  bool   `json:"local"`
	AKPath string `json:"ak_path"`
	// chroot-песочница для админов на этом хосте (пк)
	Sandbox bool `json:"sandbox"`
}

type JumpCfg struct {
	Addr string `json:"addr"`
	Port int    `json:"port"`
	User string `json:"user"`
}

type Config struct {
	Domain         string              `json:"domain"`
	Domains        []string            `json:"domains"`
	ACMEEmail      string              `json:"acme_email"`
	ACMECache      string              `json:"acme_cache"`
	DB             string              `json:"db"`
	JWTSecretFile  string              `json:"jwt_secret_file"`
	PlainListen    string              `json:"plain_listen"`
	Provisioner    string              `json:"provisioner"`
	BootstrapAdmin string              `json:"bootstrap_admin_pubkey"`
	NetToken       string              `json:"net_token"`
	Hosts          map[string]*HostCfg `json:"hosts"`
	StaticHosts    map[string]string   `json:"static_hosts"`
	ProxyHosts     map[string]string   `json:"proxy_hosts"`
	Jump           *JumpCfg            `json:"jump"`
	// 2FA: до этой unix-метки owner/admin без включённого TOTP пускаем
	// (grace на зачисление). 0 = grace нет. После метки: бамали denying.
	TwoFAGrace int64 `json:"2fa_grace_until"`
	// Песочницы админов (chroot на пк): префикс каталогов /srv/zsandbox/<user>.
	SandboxPrefix string `json:"sandbox_prefix"`
	// hwid-привязка device-токенов: при true токен, отданный одному устройству
	// (hwid), с другого железа отклоняется (нужен повторный TOTP/recovery).
	// false = только мягкая привязка (log) — для раскатки.
	HWIDEnforce bool `json:"hwid_enforce"`
	// Постоянные (вне ротыции) ключи, чьи входы ssh на hosts не считаются
	// «неизвестным устройством» в /v1/keycheck: tunnel-ключ, deploy-ключ и т.п.
	KnownKeys []string `json:"known_keys"`
	// Cloudflare API-токен (Zone.DNS:Edit для зоны apex-домена). Если задан —
	// autocert переходит на DNS-01 и добавляет wildcard *.rival-afk.com:
	// ЛЮБОЙ субдомен получает валидный TLS и попадает на заглушку
	// rival-afk.com/not-found (см. hostRouter). Пусто = как раньше.
	DNSCFToken string `json:"dns_cf_token"`
}

type Server struct {
	cfg *Config
	db  *sql.DB
	jwt []byte

	chMu    sync.Mutex
	chMap   map[string]webChallenge
	bindMu  sync.Mutex
	bindMap map[string]bindChallenge
}

type Claims struct {
	KID   string   `json:"kid"`
	UN    string   `json:"un,omitempty"`
	Role  string   `json:"role"`
	Hosts []string `json:"hosts"`
	Caps  []string `json:"caps,omitempty"`
	jwt.RegisteredClaims
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.DB == "" {
		c.DB = "/var/lib/rival/auth.db"
	}
	if c.JWTSecretFile == "" {
		c.JWTSecretFile = "/etc/rival/jwt.secret"
	}
	if c.ACMECache == "" {
		c.ACMECache = "/var/lib/rival/acme"
	}
	return &c, nil
}

func (s *Server) jwtSecret() ([]byte, error) {
	if b, err := os.ReadFile(s.cfg.JWTSecretFile); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		return []byte(strings.TrimSpace(string(b))), nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	sec := hex.EncodeToString(b)
	if err := os.MkdirAll(filepath.Dir(s.cfg.JWTSecretFile), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(s.cfg.JWTSecretFile, []byte(sec), 0o600); err != nil {
		return nil, err
	}
	return []byte(sec), nil
}

func (s *Server) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS keys (
  id TEXT PRIMARY KEY,
  pubkey TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL,
  hosts TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  caps TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS issued (
  id TEXT PRIMARY KEY,
  key_id TEXT NOT NULL,
  host TEXT NOT NULL,
  ssh_pubkey TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS net_peers (
  label TEXT PRIMARY KEY,
  ip TEXT NOT NULL,
  meta TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pass_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  caps TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rustlings_progress (
  user_id TEXT NOT NULL,
  course_id TEXT NOT NULL,
  slug TEXT NOT NULL,
  completed INTEGER NOT NULL DEFAULT 0,
  visited_at TEXT,
  completed_at TEXT,
  PRIMARY KEY (user_id, course_id, slug)
);
CREATE TABLE IF NOT EXISTS rustlings_last_lesson (
  user_id TEXT NOT NULL,
  course_id TEXT NOT NULL,
  slug TEXT NOT NULL,
  title TEXT,
  updated_at TEXT,
  PRIMARY KEY (user_id, course_id)
);
CREATE TABLE IF NOT EXISTS totp (
  kid TEXT PRIMARY KEY,
  secret TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery (
  kid TEXT NOT NULL,
  code TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  used_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (kid, code)
);
CREATE TABLE IF NOT EXISTS devices (
  kid TEXT NOT NULL,
  token TEXT NOT NULL,
  created INTEGER NOT NULL,
  last_seen INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (kid, token)
);
CREATE TABLE IF NOT EXISTS keysync (
  host TEXT PRIMARY KEY,
  blob TEXT NOT NULL,
  win INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS keyfps (
  fp TEXT PRIMARY KEY,
  kid TEXT NOT NULL,
  host TEXT NOT NULL,
  hwid TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);`)
	if err != nil {
		return err
	}
	// upgrade pre-caps databases
	var cols []string
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info('keys')`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var n string
			rows.Scan(&n)
			cols = append(cols, n)
		}
	}
	hasCaps, hasUserID := false, false
	for _, c := range cols {
		if c == "caps" {
			hasCaps = true
		}
		if c == "user_id" {
			hasUserID = true
		}
	}
	if !hasCaps {
		s.db.Exec(`ALTER TABLE keys ADD COLUMN caps TEXT NOT NULL DEFAULT '[]'`)
		s.db.Exec(`UPDATE keys SET caps='["console","ssh"]' WHERE label='bootstrap-admin'`)
		s.db.Exec(`UPDATE keys SET caps='["console"]' WHERE role='admin' AND caps='[]'`)
	}
	if !hasUserID {
		s.db.Exec(`ALTER TABLE keys ADD COLUMN user_id TEXT NOT NULL DEFAULT ''`)
	}
	// hwid-привязка устройства: devices.hwid — привязывается при первом заходе,
	// после этого несовпадение = чужое железо (смотри deviceOK / HWIDEnforce)
	var devCols []string
	drows, err := s.db.Query(`SELECT name FROM pragma_table_info('devices')`)
	if err == nil {
		defer drows.Close()
		for drows.Next() {
			var n string
			drows.Scan(&n)
			devCols = append(devCols, n)
		}
	}
	hasHWID := false
	for _, c := range devCols {
		if c == "hwid" {
			hasHWID = true
		}
	}
	if !hasHWID {
		s.db.Exec(`ALTER TABLE devices ADD COLUMN hwid TEXT NOT NULL DEFAULT ''`)
	}
	// role model: the ssh cap implies the owner tier (root access to hosts)
	// историческая миграция отключена: раньше admin+ssh = owner (весь root).
	// Теперь admin+ssh = песочница chroot на пк; promotion удалён.
	return nil
}

func (s *Server) bootstrap() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM keys`).Scan(&n); err != nil {
		return err
	}
	if n > 0 || s.cfg.BootstrapAdmin == "" {
		return nil
	}
	pub := normalizePub(s.cfg.BootstrapAdmin)
	hosts := []string{}
	for h := range s.cfg.Hosts {
		hosts = append(hosts, h)
	}
	hj, _ := json.Marshal(hosts)
	id := randID()
	_, err := s.db.Exec(`INSERT INTO keys (id, pubkey, role, hosts, label, caps, created_at) VALUES (?,?,?,?,?,?,?)`,
		id, pub, "owner", string(hj), "bootstrap-admin", `["console","ssh"]`, time.Now().Unix())
	if err != nil {
		return err
	}
	log.Printf("bootstrap admin key installed: %s", id)
	return nil
}

func randID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func normalizePub(s string) string {
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(parsed)))
}

func verifyEd25519Authorized(pubSSH ssh.PublicKey, msg, sig []byte) bool {
	ck, ok := pubSSH.(ssh.CryptoPublicKey)
	if !ok {
		return false
	}
	edPub, ok := ck.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return false
	}
	return ed25519.Verify(edPub, msg, sig)
}

// ---------- 2FA (TOTP / RFC 6238) ----------

// Анти-реплей: код+секрет не принимает повторно в течение 90 с
var (
	totpSeen   = map[string]int64{}
	totpSeenMu sync.Mutex
)

func b32Encode(src []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var out strings.Builder
	buf := 0
	bits := 0
	for _, b := range src {
		buf = buf<<8 | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out.WriteByte(alphabet[(buf>>uint(bits))&31])
		}
	}
	if bits > 0 {
		out.WriteByte(alphabet[(buf<<uint(5-bits))&31])
	}
	return out.String()
}

func b32Decode(s string) ([]byte, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var out []byte
	buf, bits := 0, 0
	for _, r := range strings.ToUpper(strings.TrimRight(s, "=")) {
		i := strings.IndexRune(alphabet, r)
		if i < 0 {
			return nil, fmt.Errorf("bad base32 char %q", r)
		}
		buf = buf<<5 | i
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>uint(bits)))
		}
	}
	return out, nil
}

// totpAt — 6-значный код SHA1/30s для unix-времени t.
func totpAt(secret []byte, t int64) string {
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(t/30))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg)
	sum := mac.Sum(nil)
	o := sum[19] & 0x0f
	val := (int64(sum[o])&0x7f)<<24 | int64(sum[o+1])<<16 | int64(sum[o+2])<<8 | int64(sum[o+3])
	return fmt.Sprintf("%06d", val%1000000)
}

// checkTOTP — окно ±1 период; защита от повтора в памяти.
func (s *Server) checkTOTP(kid, secretB32, code string) bool {
	sec, err := b32Decode(secretB32)
	if err != nil || len(sec) == 0 {
		return false
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	now := time.Now().Unix()
	for _, w := range []int64{0, -1, 1} {
		c := totpAt(sec, now+w*30)
		if c == code {
			totpSeenMu.Lock()
			k := kid + "|" + c
			if prev, ok := totpSeen[k]; ok && now-prev < 90 {
				totpSeenMu.Unlock()
				return false // уже использован
			}
			totpSeen[k] = now
			totpSeenMu.Unlock()
			return true
		}
	}
	return false
}

func randToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func randB32Secret() string {
	b := make([]byte, 20)
	rand.Read(b)
	return b32Encode(b)
}

func (s *Server) totpFor(kid string) (secret string, enabled bool) {
	row := s.db.QueryRow(`SELECT secret, enabled FROM totp WHERE kid = ?`, kid)
	var sec string
	var en int
	if err := row.Scan(&sec, &en); err != nil {
		return "", false
	}
	return sec, en != 0
}

// deviceOK проверяет device-токен и его привязку к железу (hwid).
// hwid пустой (старый rsh) — только факт наличия токена. Токен без привязки
// привязывается к первому устройству, с которого пришёл (soft-bind, ротация
// ключей это не затрагивает — касается только device-токенов). Токен с
// отличным hwid = тот же файл ключа на другом устройстве → отказ (при
// HWIDEnforce) или мягкий лог; «потеря» устройства лечится повторным TOTP —
// челлендж тогда честно просит 2fa (см. twoFAChallenge).
func (s *Server) deviceOK(kid, token, hwid string) (bool, string) {
	if token == "" {
		return false, "no device token"
	}
	var stored string
	err := s.db.QueryRow(`SELECT hwid FROM devices WHERE kid = ? AND token = ?`, kid, token).Scan(&stored)
	if err == sql.ErrNoRows {
		return false, "unknown device token"
	}
	if err != nil {
		return false, "db error"
	}
	if hwid == "" || (stored != "" && stored != hwid) {
		// json: разрешён любой вход с валидным токеном (привязку не перепроверяем)
		if stored != "" && hwid != "" && stored != hwid {
			if s.cfg.HWIDEnforce {
				log.Printf("device kid=%s token=%s hwid mismatch: enforces deny", s8(kid), s8(token))
				return false, "device bound to different hardware (hwid mismatch)"
			}
			log.Printf("device kid=%s token=%s hwid mismatch (soft)", s8(kid), s8(token))
			s.db.Exec(`UPDATE devices SET last_seen = ? WHERE kid = ? AND token = ?`, time.Now().Unix(), kid, token)
			return true, "mismatch"
		}
		s.db.Exec(`UPDATE devices SET last_seen = ? WHERE kid = ? AND token = ?`, time.Now().Unix(), kid, token)
		return true, ""
	}
	if stored == hwid {
		s.db.Exec(`UPDATE devices SET last_seen = ? WHERE kid = ? AND token = ?`, time.Now().Unix(), kid, token)
		return true, ""
	}
	// stored пуст и hwid не пуст: первая привязка
	res, err := s.db.Exec(`UPDATE devices SET hwid = ?, last_seen = ? WHERE kid = ? AND token = ?`,
		hwid, time.Now().Unix(), kid, token)
	if n, _ := res.RowsAffected(); err != nil || n != 1 {
		return false, "bind failed"
	}
	log.Printf("device bound: kid=%s hwid=%s", s8(kid), s8(hwid))
	return true, "bound"
}

// twoFAChallenge решает, пропускать ли вход: device-token, TOTP, recovery,
// grace (пока секрет не включён). Возвращает (пропустить, новый device token).
func (s *Server) twoFAChallenge(w http.ResponseWriter, kid, role string, totpCode, recoveryCode, devToken, hwid string) (bool, string) {
	secret, enabled := s.totpFor(kid)
	mandatory := enabled || role == "owner" || role == "admin"

	if !mandatory {
		return true, ""
	}
	// доверенное устройство?
	if devToken != "" {
		if ok, _ := s.deviceOK(kid, devToken, hwid); ok {
			return true, devToken
		}
		// токен есть, но не прошёл (чужое железо) — молча спускаемся к TOTP
		// ниже: враг не узнаёт причину, законный владелец просто введёт код.
	}
	// TOTP (в т.ч. при включении, и если секрет есть, но ещё не confirmed
	// — тогда это фактическое подтверждение первого кода)
	if secret != "" && s.checkTOTP(kid, secret, totpCode) {
		newTok := randToken(24)
		s.db.Exec(`INSERT INTO devices (kid, token, hwid, created, last_seen) VALUES (?,?,?,?,?)`,
			kid, newTok, hwid, time.Now().Unix(), time.Now().Unix())
		if !enabled {
			s.db.Exec(`UPDATE totp SET enabled = 1 WHERE kid = ?`, kid)
		}
		return true, newTok
	}
	// recovery-код
	if recoveryCode != "" {
		res, err := s.db.Exec(`UPDATE recovery SET used = 1, used_at = ? WHERE kid = ? AND code = ? AND used = 0`,
			time.Now().Unix(), kid, strings.TrimSpace(recoveryCode))
		if err == nil {
			if n, _ := res.RowsAffected(); n == 1 {
				newTok := randToken(24)
				s.db.Exec(`INSERT INTO devices (kid, token, hwid, created, last_seen) VALUES (?,?,?,?,?)`,
					kid, newTok, hwid, time.Now().Unix(), time.Now().Unix())
				return true, newTok
			}
		}
	}
	// подготовленный к зачислению секрет отсутствует и grace ещё жив?
	if secret == "" && s.cfg.TwoFAGrace > 0 && time.Now().Unix() < s.cfg.TwoFAGrace {
		return true, ""
	}
	writeJSON(w, 200, map[string]interface{}{"need_2fa": true})
	return false, ""
}

// ---------- 2FA endpoints ----------

func (s *Server) twofaInitHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	secret, enabled := s.totpFor(claims.KID)
	if enabled {
		writeErr(w, 409, "2fa already enabled (disable first)")
		return
	}
	if secret == "" {
		secret = randB32Secret()
		s.db.Exec(`INSERT INTO totp (kid, secret, enabled, created) VALUES (?,?,0,?)`,
			claims.KID, secret, time.Now().Unix())
	}
	label := url.QueryEscape(claims.KID[:8])
	otpauth := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=rival-auth&digits=6&period=30",
		url.QueryEscape(s.cfg.Domain), label, secret)
	writeJSON(w, 200, map[string]interface{}{"secret": secret, "otpauth": otpauth})
}

func (s *Server) twofaConfirmHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	var req struct {
		Code string `json:"code"`
		HWID string `json:"hwid,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	secret, _ := s.totpFor(claims.KID)
	if secret == "" {
		writeErr(w, 400, "no pending 2fa secret (run 2fa init)")
		return
	}
	if !s.checkTOTP(claims.KID, secret, req.Code) {
		writeErr(w, 401, "wrong code")
		return
	}
	s.db.Exec(`UPDATE totp SET enabled = 1 WHERE kid = ?`, claims.KID)
	s.db.Exec(`DELETE FROM recovery WHERE kid = ?`, claims.KID)
	var codes []string
	for i := 0; i < 6; i++ {
		c := randToken(4) // 8 hex
		codes = append(codes, c)
		s.db.Exec(`INSERT INTO recovery (kid, code, used, used_at) VALUES (?,?,0,0)`, claims.KID, c)
	}
	newTok := randToken(24)
	s.db.Exec(`INSERT OR REPLACE INTO devices (kid, token, hwid, created, last_seen) VALUES (?,?,?,?,?)`,
		claims.KID, newTok, req.HWID, time.Now().Unix(), time.Now().Unix())
	writeJSON(w, 200, map[string]interface{}{
		"enabled": true, "recovery": codes, "device_token": newTok,
	})
}

func (s *Server) twofaDisableHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// подтвердить владение кодом/recovery
	var req struct {
		Code string `json:"code"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	secret, enabled := s.totpFor(claims.KID)
	okCode := false
	if enabled && s.checkTOTP(claims.KID, secret, req.Code) {
		okCode = true
	}
	if !okCode && req.Code != "" {
		res, err := s.db.Exec(`UPDATE recovery SET used = 1, used_at = ? WHERE kid = ? AND code = ? AND used = 0`,
			time.Now().Unix(), claims.KID, strings.TrimSpace(req.Code))
		if n, _ := res.RowsAffected(); err == nil && n == 1 {
			okCode = true
		}
	}
	if !okCode {
		writeErr(w, 401, "wrong code")
		return
	}
	s.db.Exec(`DELETE FROM totp WHERE kid = ?`, claims.KID)
	s.db.Exec(`DELETE FROM recovery WHERE kid = ?`, claims.KID)
	writeJSON(w, 200, map[string]interface{}{"disabled": true})
}

func (s *Server) twofaStatusHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	_, enabled := s.totpFor(claims.KID)
	var ndev, nrec int
	s.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE kid = ?`, claims.KID).Scan(&ndev)
	s.db.QueryRow(`SELECT COUNT(*) FROM recovery WHERE kid = ? AND used = 0`, claims.KID).Scan(&nrec)
	writeJSON(w, 200, map[string]interface{}{
		"enabled": enabled, "devices": ndev, "recovery_left": nrec,
		"grace_until": s.cfg.TwoFAGrace,
	})
}

func (s *Server) authHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pubkey       string `json:"pubkey"`
		TS           int64  `json:"ts"`
		Sig          string `json:"sig"`
		DeviceToken  string `json:"device_token,omitempty"`
		TOTP         string `json:"totp,omitempty"`
		RecoveryCode string `json:"recovery,omitempty"`
		HWID         string `json:"hwid,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad request")
		return
	}
	pub := normalizePub(req.Pubkey)
	if pub == "" || req.Sig == "" {
		writeErr(w, 400, "missing fields")
		return
	}
	if d := time.Now().Unix() - req.TS; d > 300 || d < -300 {
		writeErr(w, 401, "timestamp out of window")
		return
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
	if err != nil {
		writeErr(w, 400, "bad pubkey")
		return
	}
	var keyID, role, hostsJSON, label, capsJSON string
	err = s.db.QueryRow(`SELECT id, role, hosts, label, caps FROM keys WHERE pubkey = ?`, pub).
		Scan(&keyID, &role, &hostsJSON, &label, &capsJSON)
	if err != nil {
		writeErr(w, 401, "unknown key")
		return
	}
	sig, err := hex.DecodeString(strings.TrimSpace(req.Sig))
	if err != nil {
		writeErr(w, 400, "bad sig encoding")
		return
	}
	msg := fmt.Sprintf("rival-auth-v1|%s|%d", pub, req.TS)
	if !verifyEd25519Authorized(parsed, []byte(msg), sig) {
		writeErr(w, 401, "bad signature")
		return
	}
	var hosts, caps []string
	json.Unmarshal([]byte(hostsJSON), &hosts)
	json.Unmarshal([]byte(capsJSON), &caps)

	// 2FA-челлендж (до выпуска токена); разблокировка: device token, TOTP или
	// recovery-код. Новорегистрируемые без секрета проходят, пока жив grace.
	passed, devTok := s.twoFAChallenge(w, keyID, role, req.TOTP, req.RecoveryCode, req.DeviceToken, req.HWID)
	if !passed {
		return
	}

	exp := time.Now().Add(time.Hour)
	claims := Claims{
		KID:   keyID,
		Role:  role,
		Hosts: hosts,
		Caps:  caps,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(exp),
			Issuer:    "rival-auth",
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok, err := t.SignedString(s.jwt)
	if err != nil {
		writeErr(w, 500, "token error")
		return
	}
	resp := map[string]interface{}{
		"token": tok,
		"role":  role,
		"hosts": hosts,
		"caps":  caps,
		"exp":   exp.Unix(),
	}
	if devTok != "" {
		resp["device_token"] = devTok
	}
	_, totpEnabled := s.totpFor(keyID)
	if (role == "owner" || role == "admin") && !totpEnabled {
		resp["2fa_warning"] = "2fa not enrolled: run `rsh 2fa init` now"
	}
	writeJSON(w, 200, resp)
}

// clientIP — публичный IP клиента (моён auth-сервера): для -t (право на tmp-папку).
func clientIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		return v
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return h
}

func (s *Server) sshkeyHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !hasCap(claims, "ssh") {
		writeErr(w, 403, "ssh capability required")
		return
	}
	var req struct {
		Host string `json:"host"`
		HWID string `json:"hwid,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad request")
		return
	}
	hcfg, ok := s.cfg.Hosts[req.Host]
	if !ok {
		writeErr(w, 404, "unknown host")
		return
	}
	allowed := false
	for _, h := range claims.Hosts {
		if h == req.Host {
			allowed = true
			break
		}
	}
	if !allowed {
		writeErr(w, 403, "host not allowed for this key")
		return
	}
	role := claims.Role
	// ttl-слоты: комментарий несёт время выдачи — старые неактивные слоты
	// чистятся при следующем provision того же kid+host
	targetComment := fmt.Sprintf("rt:%s:%s:%d", claims.KID, req.Host, time.Now().Unix())
	tPriv, tPub, err := genKeyPair(targetComment)
	if err != nil {
		writeErr(w, 500, "keygen: "+err.Error())
		return
	}

	respUser := hcfg.User
	if role == "admin" {
		// админ имеет право ssh только в chroot-песочницу на пк
		if !hcfg.Sandbox {
			writeErr(w, 403, "admin role: ssh allowed only to sandbox hosts (pc)")
			return
		}
		user, err := sandboxUser(claims.KID)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if err := s.provisionAdmin(hcfg, user, tPub, targetComment); err != nil {
			writeErr(w, 500, "provision sandbox: "+err.Error())
			return
		}
		respUser = user
	} else if err := s.provision(hcfg, tPub, false); err != nil {
		writeErr(w, 500, "provision target: "+err.Error())
		return
	}

	resp := map[string]interface{}{
		"host":        req.Host,
		"user":        respUser,
		"addr":        hcfg.Addr,
		"port":        hcfg.Port,
		"private_key": string(tPriv),
		"client_ip":   clientIP(r),
	}
	if role == "admin" {
		resp["sandbox"] = true
	}

	if !hcfg.Local && s.cfg.Jump != nil {
		jumpComment := "rj:" + claims.KID
		if role == "admin" {
			// админу из джамп-слота запрещён -W куда-либо кроме pc:22
			jumpComment = "rj:" + claims.KID + ":pc"
		}
		jPriv, jPub, err := genKeyPair(jumpComment)
		if err != nil {
			writeErr(w, 500, "jump keygen: "+err.Error())
			return
		}
		vps := s.cfg.Hosts["vps"]
		if vps == nil {
			writeErr(w, 500, "no vps host config for jump")
			return
		}
		jumpOpts := `command="/bin/false",restrict,port-forwarding,permitopen="127.0.0.1:2222" `
		var err2 error
		if role == "admin" {
			err2 = s.provisionLocal(vps, jPub, jumpOpts)
		} else {
			err2 = s.provisionLocal(vps, jPub, "")
		}
		if err2 != nil {
			writeErr(w, 500, "provision jump: "+err2.Error())
			return
		}
		if jp, _, _, _, jperr := ssh.ParseAuthorizedKey([]byte(jPub)); jperr == nil {
			s.db.Exec(`INSERT OR REPLACE INTO keyfps (fp, kid, host, hwid, created_at) VALUES (?,?,?,?,?)`,
				ssh.FingerprintSHA256(jp), claims.KID, "vps", req.HWID, time.Now().Unix())
		}
		resp["jump"] = map[string]interface{}{
			"addr":        s.cfg.Jump.Addr,
			"port":        s.cfg.Jump.Port,
			"user":        s.cfg.Jump.User,
			"private_key": string(jPriv),
		}
	}

	s.db.Exec(`INSERT INTO issued (id, key_id, host, ssh_pubkey, created_at) VALUES (?,?,?,?,?)`,
		randID(), claims.KID, req.Host, tPub, time.Now().Unix())
	// fingerprint выданного слота — вотчдог сверяет входы через /v1/keycheck:
	// вход живым rt-слотом известен, «ручной» чужой ключ — нет
	if parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(tPub)); err == nil {
		s.db.Exec(`INSERT OR REPLACE INTO keyfps (fp, kid, host, hwid, created_at) VALUES (?,?,?,?,?)`,
			ssh.FingerprintSHA256(parsed), claims.KID, req.Host, req.HWID, time.Now().Unix())
	}

	writeJSON(w, 200, resp)
}

// s8 — безопасное усечение для логов.
func s8(v string) string {
	if len(v) > 8 {
		return v[:8]
	}
	return v
}

// keycheckHandler: знает ли auth такой ssh-ключ (по fingerprint)?
// Только для loopback — зовёт локальный вотчдог vps при разборе входов ssh.
// known = зарегистрированный ключ (caps ssh) ИЛИ живой ttl-слот (rt, ≤3 ч)
// ИЛИ закреплённый в auth.json known_keys (tunnel/deploy и т.п.).
// IP клиента НЕ согласовывается — IP динамические, доверие через железо.
func (s *Server) keycheckHandler(w http.ResponseWriter, r *http.Request) {
	switch ip := clientIP(r); ip {
	case "127.0.0.1", "::1":
	default:
		writeErr(w, 403, "local only")
		return
	}
	var req struct {
		FP string `json:"fp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.FP) == "" {
		writeErr(w, 400, "bad request")
		return
	}
	req.FP = strings.TrimSpace(req.FP)
	kind := ""
	// 1) зарегистрированные ключи (owner/admin с капой ssh)
	rows, err := s.db.Query(`SELECT pubkey, caps FROM keys`)
	if err == nil {
		for rows.Next() {
			var pub, caps string
			if rows.Scan(&pub, &caps) != nil || !strings.Contains(caps, "ssh") {
				continue
			}
			if parsed, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(normalizePub(pub))); perr == nil {
				if ssh.FingerprintSHA256(parsed) == req.FP {
					kind = "device"
					break
				}
			}
		}
		rows.Close()
	}
	// 2) живые ttl-слоты rsh (ротация ключей — их не трогаем, они известны)
	if kind == "" {
		var n int
		if s.db.QueryRow(`SELECT COUNT(*) FROM keyfps WHERE fp = ? AND created_at > ?`,
			req.FP, time.Now().Add(-3*time.Hour).Unix()).Scan(&n); n > 0 {
			kind = "slot"
		}
	}
	// 3) закреплённые оператором (tunnel-ключ, deploy-ключ, ...)
	if kind == "" {
		for _, line := range s.cfg.KnownKeys {
			if parsed, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(normalizePub(line))); perr == nil {
				if ssh.FingerprintSHA256(parsed) == req.FP {
					kind = "known"
					break
				}
			}
		}
	}
	writeJSON(w, 200, map[string]interface{}{"known": kind != "", "kind": kind})
}

func (s *Server) adminKeysHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !isAdminRole(claims.Role) {
		writeErr(w, 403, "admin only")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.Query(`SELECT id, pubkey, role, hosts, label, caps, created_at FROM keys ORDER BY created_at`)
		if err != nil {
			writeErr(w, 500, "db error")
			return
		}
		defer rows.Close()
		out := []map[string]interface{}{}
		for rows.Next() {
			var id, pub, role, hostsJSON, label, capsJSON string
			var ca int64
			rows.Scan(&id, &pub, &role, &hostsJSON, &label, &capsJSON, &ca)
			var hosts, caps []string
			json.Unmarshal([]byte(hostsJSON), &hosts)
			json.Unmarshal([]byte(capsJSON), &caps)
			out = append(out, map[string]interface{}{
				"id": id, "pubkey": pub, "role": role, "hosts": hosts,
				"label": label, "caps": caps, "created_at": ca,
			})
		}
		writeJSON(w, 200, out)
	case http.MethodPost:
		var req struct {
			Pubkey string   `json:"pubkey"`
			Role   string   `json:"role"`
			Hosts  []string `json:"hosts"`
			Label  string   `json:"label"`
			Caps   []string `json:"caps"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, 400, "bad request")
			return
		}
		if !validRole(req.Role) {
			writeErr(w, 400, "role must be user, admin or owner")
			return
		}
		if !canAssignRole(claims, req.Role) {
			writeErr(w, 403, "only owners can assign the owner role")
			return
		}
		if !validCaps(req.Caps) {
			writeErr(w, 400, "caps must be console and/or ssh")
			return
		}
		if len(req.Caps) == 0 && isAdminRole(req.Role) {
			req.Caps = []string{"console"}
		}
		if msg := capsRoleError(req.Role, req.Caps); msg != "" {
			writeErr(w, 400, msg)
			return
		}
		// hierarchy: cannot grant caps you don't have yourself
		if !canGrantCaps(claims, req.Caps) {
			writeErr(w, 403, "cannot grant caps you don't have")
			return
		}
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(req.Pubkey))); err != nil {
			writeErr(w, 400, "bad pubkey")
			return
		}
		req.Pubkey = normalizePub(req.Pubkey)
		if len(req.Hosts) == 0 {
			for h := range s.cfg.Hosts {
				req.Hosts = append(req.Hosts, h)
			}
		}
		for _, h := range req.Hosts {
			if _, ok := s.cfg.Hosts[h]; !ok {
				writeErr(w, 400, "unknown host: "+h)
				return
			}
		}
		hj, _ := json.Marshal(req.Hosts)
		cj, _ := json.Marshal(req.Caps)
		id := randID()
		_, err := s.db.Exec(`INSERT INTO keys (id, pubkey, role, hosts, label, caps, created_at) VALUES (?,?,?,?,?,?,?)`,
			id, strings.TrimSpace(req.Pubkey), req.Role, string(hj), req.Label, string(cj), time.Now().Unix())
		if err != nil {
			writeErr(w, 409, "key already exists or db error")
			return
		}
		writeJSON(w, 200, map[string]interface{}{"id": id, "caps": req.Caps})
	default:
		writeErr(w, 405, "method not allowed")
	}
}

func (s *Server) adminKeyDeleteHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !isAdminRole(claims.Role) {
		writeErr(w, 403, "admin only")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, 400, "missing id")
		return
	}
	res, err := s.db.Exec(`DELETE FROM keys WHERE id = ?`, id)
	if err != nil {
		writeErr(w, 500, "db error")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, 404, "not found")
		return
	}
	writeJSON(w, 200, map[string]interface{}{"deleted": id})
}

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) (*Claims, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		writeErr(w, 401, "missing bearer token")
		return nil, false
	}
	tok := strings.TrimPrefix(h, "Bearer ")
	var c Claims
	parsed, err := jwt.ParseWithClaims(tok, &c, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected alg")
		}
		return s.jwt, nil
	})
	if err != nil || !parsed.Valid {
		writeErr(w, 401, "invalid token")
		return nil, false
	}
	return &c, true
}

func (s *Server) netAuthorized(r *http.Request) bool {
	if s.cfg.NetToken == "" {
		return false
	}
	h := r.Header.Get("Authorization")
	return h == "Bearer "+s.cfg.NetToken
}

func (s *Server) netAnnounceHandler(w http.ResponseWriter, r *http.Request) {
	if !s.netAuthorized(r) {
		writeErr(w, 401, "invalid net token")
		return
	}
	var req struct {
		Label string            `json:"label"`
		IP    string            `json:"ip"`
		Peers map[string]string `json:"peers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad request")
		return
	}
	if req.Label == "" || req.IP == "" {
		writeErr(w, 400, "label and ip required")
		return
	}
	now := time.Now().Unix()
	meta, _ := json.Marshal(map[string]interface{}{"peers": req.Peers})
	s.db.Exec(`INSERT INTO net_peers (label, ip, meta, updated_at) VALUES (?,?,?,?)
	           ON CONFLICT(label) DO UPDATE SET ip=excluded.ip, meta=excluded.meta, updated_at=excluded.updated_at`,
		req.Label, req.IP, string(meta), now)
	// also record discovered peers so they are queryable
	for pl, pip := range req.Peers {
		if pl == "" || pip == "" {
			continue
		}
		s.db.Exec(`INSERT INTO net_peers (label, ip, meta, updated_at) VALUES (?,?,?,?)
		           ON CONFLICT(label) DO UPDATE SET ip=excluded.ip, updated_at=excluded.updated_at`,
			pl, pip, `"discovered"`, now)
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "label": req.Label, "ip": req.IP, "ts": now})
}

func (s *Server) netPeersHandler(w http.ResponseWriter, r *http.Request) {
	if !s.netAuthorized(r) {
		writeErr(w, 401, "invalid net token")
		return
	}
	rows, err := s.db.Query(`SELECT label, ip, updated_at FROM net_peers ORDER BY updated_at DESC`)
	if err != nil {
		writeErr(w, 500, "db error")
		return
	}
	defer rows.Close()
	out := []map[string]interface{}{}
	for rows.Next() {
		var label, ip string
		var ts int64
		rows.Scan(&label, &ip, &ts)
		out = append(out, map[string]interface{}{"label": label, "ip": ip, "updated_at": ts})
	}
	writeJSON(w, 200, out)
}

func (s *Server) netPeerHandler(w http.ResponseWriter, r *http.Request) {
	if !s.netAuthorized(r) {
		writeErr(w, 401, "invalid net token")
		return
	}
	label := r.PathValue("label")
	var ip string
	var ts int64
	err := s.db.QueryRow(`SELECT ip, updated_at FROM net_peers WHERE label = ?`, label).Scan(&ip, &ts)
	if err != nil {
		writeErr(w, 404, "unknown peer")
		return
	}
	writeJSON(w, 200, map[string]interface{}{"label": label, "ip": ip, "updated_at": ts})
}

// keysyncHandler — шифрованный обмен pub-ключами между устройствами.
// Сервер — глухой релей: не держит общий секрет и не может расшифровать блобы
// (AES-256-GCM, ключ = SHA256("rsh-keysync-v1" || secret || window), окно 5 мин).
// Каждый узел публикует свои pub-ключи и забирает чужие; приёмник сам дополняет
// свой authorized_keys недостающими строками (append-only).
func (s *Server) keysyncHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !isAdminRole(claims.Role) {
		writeErr(w, 403, "owner/admin only")
		return
	}
	var req struct {
		Host string `json:"host"`
		Blob string `json:"blob"`
		Win  int64  `json:"win"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, 400, "bad request")
		return
	}
	if len(req.Blob) > 40<<10 {
		writeErr(w, 413, "blob too large")
		return
	}
	allowed := false
	for _, h := range claims.Hosts {
		if h == req.Host {
			allowed = true
			break
		}
	}
	if !allowed {
		writeErr(w, 403, "host not allowed for this key")
		return
	}
	now := time.Now().Unix()
	// upsert блоба публикующего узла
	if req.Blob != "" && req.Host != "" {
		if _, err := s.db.Exec(`INSERT INTO keysync (host, blob, win, updated_at) VALUES (?, ?, ?, ?)
			ON CONFLICT(host) DO UPDATE SET blob=excluded.blob, win=excluded.win, updated_at=excluded.updated_at`,
			req.Host, req.Blob, req.Win, now); err != nil {
			writeErr(w, 500, "db: "+err.Error())
			return
		}
	}
	rows, err := s.db.Query(`SELECT host, blob, win, updated_at FROM keysync ORDER BY host`)
	if err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	type peer struct {
		Host    string `json:"host"`
		Blob    string `json:"blob"`
		Win     int64  `json:"win"`
		Updated int64  `json:"updated_at"`
	}
	var peers []peer
	for rows.Next() {
		var p peer
		if err := rows.Scan(&p.Host, &p.Blob, &p.Win, &p.Updated); err != nil {
			rows.Close()
			writeErr(w, 500, "db: "+err.Error())
			return
		}
		if p.Host == req.Host {
			continue // чужие блобы: свой возвращать незачем
		}
		// блобы старше 2 ч считаем протухшими и не отдаём
		if now-p.Updated > 7200 {
			continue
		}
		peers = append(peers, p)
	}
	rows.Close()
	writeJSON(w, 200, map[string]interface{}{"peers": peers, "now": now})
}

func (s *Server) provision(hcfg *HostCfg, pubLine string, restricted bool) error {
	if hcfg.Local {
		return s.provisionLocal(hcfg, pubLine, "")
	}
	_ = restricted
	ak := hcfg.AKPath
	if ak == "" {
		ak = "~/.ssh/authorized_keys"
	}
	comment := extractComment(pubLine)
	line := pubLine
	if restricted {
		line = `command="/bin/false",restrict,port-forwarding ` + pubLine
	}
	// ttl-слоты: comment виду rt:<kid>:<host>:<unix-ts>; профилактически удаляем
	// свои слоты старше slotTTL (неактивные строки чужих ключ-id и legacy не трогаем)
	prefix := rtSlotPrefix(comment) + ":"
	cutoff := time.Now().Add(-slotTTL).Unix()
	remote := fmt.Sprintf(
		"mkdir -p $(dirname %[1]s) && touch %[1]s && chmod 700 $(dirname %[1]s) && chmod 600 %[1]s && awk -v p='%[2]s' -v c=%[3]d '{ if (index($0, p) > 0) { ts=substr($0, index($0, p)+length(p)); gsub(/[^0-9].*/, \"\", ts); if (ts+0 < c) next } print }' %[1]s > %[1]s.tmp && mv %[1]s.tmp %[1]s && chmod 600 %[1]s && echo '%[4]s' >> %[1]s",
		ak, prefix, cutoff, line)
	args := []string{
		"-i", s.cfg.Provisioner,
		"-p", fmt.Sprintf("%d", hcfg.Port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
		fmt.Sprintf("%s@%s", hcfg.User, hcfg.Addr),
		remote,
	}
	out, err := exec.Command("ssh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *Server) provisionLocal(hcfg *HostCfg, pubLine string, opts string) error {
	ak := hcfg.AKPath
	if ak == "" {
		ak = "/root/.ssh/authorized_keys"
	}
	comment := extractComment(pubLine)
	line := pubLine
	if opts != "" {
		line = opts + pubLine
	}
	if err := os.MkdirAll(filepath.Dir(ak), 0o700); err != nil {
		return err
	}
	prefix := rtSlotPrefix(comment) + ":"
	cut := time.Now().Add(-slotTTL).Unix()
	var keep []string
	if b, err := os.ReadFile(ak); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(l) == "" {
				continue
			}
			// ttl-слоты rt:<kid>:<host>:<ts>: удаляем свои с ts < cut;
			// legacy (без ts) и чужие комментарии не трогаем
			if i := strings.Index(l, prefix); i >= 0 {
				dig := ""
				for _, r := range l[i+len(prefix):] {
					if r < '0' || r > '9' {
						break
					}
					dig += string(r)
				}
				if dig != "" {
					var t int64
					fmt.Sscanf(dig, "%d", &t)
					if t < cut {
						continue
					}
				}
			}
			keep = append(keep, l)
		}
	}
	keep = append(keep, line)
	return os.WriteFile(ak, []byte(strings.Join(keep, "\n")+"\n"), 0o600)
}

const slotTTL = 2 * time.Hour

// rtSlotPrefix: "rt:<kid>:<host>:<ts>" -> "rt:<kid>:<host>" (без хвоста-времени)
func rtSlotPrefix(comment string) string {
	i := strings.LastIndex(comment, ":")
	if i < 0 {
		return comment
	}
	return comment[:i]
}

func extractComment(pubLine string) string {
	parts := strings.Fields(strings.TrimSpace(pubLine))
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

func genKeyPair(comment string) ([]byte, string, error) {
	dir, err := os.MkdirTemp("", "rivalkey")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "k")
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-f", path, "-q")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, "", fmt.Errorf("%v: %s", err, string(out))
	}
	priv, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	pub, err := os.ReadFile(path + ".pub")
	if err != nil {
		return nil, "", err
	}
	return priv, strings.TrimSpace(string(pub)), nil
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /stats", s.statsJSONHandler)
	mux.HandleFunc("GET /", s.rootHandler)
	mux.HandleFunc("POST /v1/auth", s.authHandler)
	mux.HandleFunc("POST /v1/keysync", s.keysyncHandler)
	mux.HandleFunc("POST /v1/sshkey", s.sshkeyHandler)
	mux.HandleFunc("POST /v1/keycheck", s.keycheckHandler)
	mux.HandleFunc("GET /v1/admin/keys", s.adminKeysHandler)
	mux.HandleFunc("POST /v1/admin/keys", s.adminKeysHandler)
	mux.HandleFunc("DELETE /v1/admin/keys/{id}", s.adminKeyDeleteHandler)
	mux.HandleFunc("POST /v1/net/announce", s.netAnnounceHandler)
	mux.HandleFunc("GET /v1/net/peers", s.netPeersHandler)
	mux.HandleFunc("GET /v1/net/peer/{label}", s.netPeerHandler)
	// web console (mind.rival-afk.com/console, login on auth.rival-afk.com)
	mux.HandleFunc("GET /error", s.errorPageHandler)
	mux.HandleFunc("GET /login", s.loginPageHandler)
	mux.HandleFunc("GET /console", s.consolePageHandler)
	mux.HandleFunc("GET /console/ws", s.consoleWSHandler)
	mux.HandleFunc("GET /console/ssh", s.consoleSSHHandler)
	mux.HandleFunc("GET /console/xterm.min.css", s.consoleStaticHandler)
	mux.HandleFunc("GET /console/xterm.min.js", s.consoleStaticHandler)
	mux.HandleFunc("GET /console/fit.min.js", s.consoleStaticHandler)
	mux.HandleFunc("GET /console/gasoek.ttf", s.consoleStaticHandler)
	mux.HandleFunc("GET /console/inter-400.ttf", s.consoleStaticHandler)
	mux.HandleFunc("GET /console/inter-500.ttf", s.consoleStaticHandler)
	mux.HandleFunc("GET /console/inter-700.ttf", s.consoleStaticHandler)
	mux.HandleFunc("GET /console/jbmono-400.ttf", s.consoleStaticHandler)
	mux.HandleFunc("GET /console/jbmono-500.ttf", s.consoleStaticHandler)
	mux.HandleFunc("POST /v1/web/challenge", s.challengeHandler)
	mux.HandleFunc("POST /v1/web/login", s.webLoginHandler)
	mux.HandleFunc("POST /v1/web/register", s.webRegisterHandler)
	mux.HandleFunc("POST /v1/web/passlogin", s.webPassLoginHandler)
	mux.HandleFunc("POST /v1/web/bindnonce", s.webBindNonceHandler)
	mux.HandleFunc("POST /v1/web/bindkey", s.webBindKeyHandler)
	mux.HandleFunc("GET /v1/web/logout", s.webLogoutHandler)
	mux.HandleFunc("GET /v1/admin/users", s.adminUsersHandler)
	mux.HandleFunc("POST /v1/admin/users", s.adminUsersHandler)
	mux.HandleFunc("POST /v1/2fa/init", s.twofaInitHandler)
	mux.HandleFunc("POST /v1/2fa/confirm", s.twofaConfirmHandler)
	mux.HandleFunc("POST /v1/2fa/disable", s.twofaDisableHandler)
	mux.HandleFunc("GET /v1/2fa/status", s.twofaStatusHandler)
	mux.HandleFunc("PATCH /v1/admin/users/{id}", s.adminUserUpdateHandler)
	mux.HandleFunc("DELETE /v1/admin/users/{id}", s.adminUserDeleteHandler)
	mux.HandleFunc("GET /v1/console/status", s.consoleStatusHandler)
	mux.HandleFunc("POST /v1/console/service", s.consoleServiceHandler)
	mux.HandleFunc("GET /v1/console/files", s.consoleFilesHandler)
	mux.HandleFunc("POST /v1/console/fetch", s.consoleFetchHandler)
	mux.HandleFunc("DELETE /v1/console/file", s.consoleFileDeleteHandler)
	return mux
}

func main() {
	cfgPath := "/etc/rival/auth.json"
	if len(os.Args) > 2 && os.Args[1] == "-config" {
		cfgPath = os.Args[2]
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DB), 0o700); err != nil {
		log.Fatalf("db dir: %v", err)
	}
	db, err := sql.Open("sqlite", "file:"+cfg.DB+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	s := &Server{cfg: cfg, db: db, chMap: map[string]webChallenge{}, bindMap: map[string]bindChallenge{}}
	s.jwt, err = s.jwtSecret()
	if err != nil {
		log.Fatalf("jwt secret: %v", err)
	}
	if err := s.migrate(); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	if err := s.bootstrap(); err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	handler := s.hostRouter(s.mux())

	if cfg.PlainListen != "" {
		go func() {
			log.Printf("plain http on %s", cfg.PlainListen)
			if err := http.ListenAndServe(cfg.PlainListen, handler); err != nil {
				log.Printf("plain listen: %v", err)
			}
		}()
	}

	if len(cfg.Domains) > 0 || cfg.Domain != "" {
		domains := cfg.Domains
		if len(domains) == 0 {
			domains = []string{cfg.Domain}
		}
		if cfg.Domain != "" && !containsStr(domains, cfg.Domain) {
			domains = append(domains, cfg.Domain)
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domains...),
			Cache:      autocert.DirCache(cfg.ACMECache),
			Email:      cfg.ACMEEmail,
		}
		// DNS-01 через Cloudflare: wildcard *.rival-afk.com — любой субдомен
		// получает валидный TLS и попадает на заглушку /not-found (hostRouter).
		var wcman *wildcardMan
		if cfg.DNSCFToken != "" {
			wcman = newWildcardMan(cfg)
			log.Printf("dns-01 (cloudflare) включён: wildcard *.rival-afk.com")
		}
		go func() {
			log.Printf("acme http-01 on :80")
			if err := http.ListenAndServe(":80", m.HTTPHandler(nil)); err != nil {
				log.Printf("acme http: %v", err)
			}
		}()
		tlsCfg := m.TLSConfig()
		if wcman != nil {
			// fallback: неизвестный субдомен (нет своего сертификата) →
			// отдаём wildcard *.rival-afk.com — handshake проходит, дальше
			// hostRouter перекидывает на /not-found
			base := tlsCfg.GetCertificate
			tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				crt, err := base(hello)
				if err == nil && crt != nil {
					return crt, nil
				}
				if wc := wcman.get(); wc != nil {
					return wc, nil
				}
				return nil, err
			}
			wcman.start(context.Background())
		}
		https := &http.Server{
			Addr:      ":443",
			Handler:   handler,
			TLSConfig: tlsCfg,
		}
		log.Printf("https on :443 (autocert for %v)", domains)
		if err := https.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("https: %v", err)
		}
	} else {
		select {}
	}
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
