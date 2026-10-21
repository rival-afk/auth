package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
	// role model: the ssh cap implies the owner tier (root access to hosts)
	s.db.Exec(`UPDATE keys SET role='owner' WHERE role='admin' AND caps LIKE '%"ssh"%'`)
	s.db.Exec(`UPDATE users SET role='owner' WHERE role='admin' AND caps LIKE '%"ssh"%'`)
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

func (s *Server) authHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pubkey string `json:"pubkey"`
		TS     int64  `json:"ts"`
		Sig    string `json:"sig"`
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
	writeJSON(w, 200, map[string]interface{}{
		"token": tok,
		"role":  role,
		"hosts": hosts,
		"caps":  caps,
		"exp":   exp.Unix(),
	})
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

	targetComment := "rt:" + claims.KID + ":" + req.Host
	tPriv, tPub, err := genKeyPair(targetComment)
	if err != nil {
		writeErr(w, 500, "keygen: "+err.Error())
		return
	}
	if err := s.provision(hcfg, tPub, false); err != nil {
		writeErr(w, 500, "provision target: "+err.Error())
		return
	}

	resp := map[string]interface{}{
		"host":        req.Host,
		"user":        hcfg.User,
		"addr":        hcfg.Addr,
		"port":        hcfg.Port,
		"private_key": string(tPriv),
	}

	if !hcfg.Local && s.cfg.Jump != nil {
		jumpComment := "rj:" + claims.KID
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
		if err := s.provisionLocal(vps, jPub, true); err != nil {
			writeErr(w, 500, "provision jump: "+err.Error())
			return
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

	writeJSON(w, 200, resp)
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

func (s *Server) provision(hcfg *HostCfg, pubLine string, restricted bool) error {
	if hcfg.Local {
		return s.provisionLocal(hcfg, pubLine, restricted)
	}
	ak := hcfg.AKPath
	if ak == "" {
		ak = "~/.ssh/authorized_keys"
	}
	comment := extractComment(pubLine)
	line := pubLine
	if restricted {
		line = `command="/bin/false",restrict,port-forwarding ` + pubLine
	}
	remote := fmt.Sprintf(
		"mkdir -p $(dirname %[1]s) && touch %[1]s && chmod 700 $(dirname %[1]s) && chmod 600 %[1]s && sed -i '\\| %[2]s|d' %[1]s && echo '%[3]s' >> %[1]s",
		ak, comment, line)
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

func (s *Server) provisionLocal(hcfg *HostCfg, pubLine string, restricted bool) error {
	ak := hcfg.AKPath
	if ak == "" {
		ak = "/root/.ssh/authorized_keys"
	}
	comment := extractComment(pubLine)
	line := pubLine
	if restricted {
		line = `command="/bin/false",restrict,port-forwarding ` + pubLine
	}
	if err := os.MkdirAll(filepath.Dir(ak), 0o700); err != nil {
		return err
	}
	var keep []string
	if b, err := os.ReadFile(ak); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(l) == "" {
				continue
			}
			if strings.Contains(l, " "+comment) {
				continue
			}
			keep = append(keep, l)
		}
	}
	keep = append(keep, line)
	return os.WriteFile(ak, []byte(strings.Join(keep, "\n")+"\n"), 0o600)
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
	mux.HandleFunc("POST /v1/sshkey", s.sshkeyHandler)
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
		go func() {
			log.Printf("acme http-01 on :80")
			if err := http.ListenAndServe(":80", m.HTTPHandler(nil)); err != nil {
				log.Printf("acme http: %v", err)
			}
		}()
		https := &http.Server{
			Addr:      ":443",
			Handler:   handler,
			TLSConfig: m.TLSConfig(),
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
