package main

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

//go:embed web
var webFS embed.FS

// ---- web session (cookie JWT) ----

const webCookie = "rival_web"

func hasCap(c *Claims, cap string) bool {
	for _, x := range c.Caps {
		if x == cap {
			return true
		}
	}
	return false
}

func (s *Server) webClaims(r *http.Request) (*Claims, bool) {
	ck, err := r.Cookie(webCookie)
	if err != nil || ck.Value == "" {
		return nil, false
	}
	var c Claims
	parsed, err := jwt.ParseWithClaims(ck.Value, &c, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected alg")
		}
		return s.jwt, nil
	})
	if err != nil || !parsed.Valid {
		return nil, false
	}
	return &c, true
}

func (s *Server) issueWebCookie(w http.ResponseWriter, c *Claims) {
	c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour))
	c.IssuedAt = jwt.NewNumericDate(time.Now())
	c.Issuer = "rival-auth"
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	tok, err := t.SignedString(s.jwt)
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     webCookie,
		Value:    tok,
		Path:     "/",
		Domain:   ".rival-afk.com",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 3600,
	})
}

// requireWebCap: cookie session + capability check. HTML pages redirect to login.
func (s *Server) requireWebCap(w http.ResponseWriter, r *http.Request, cap string, html bool) (*Claims, bool) {
	c, ok := s.webClaims(r)
	if !ok {
		if html {
			rd := url.QueryEscape("https://" + r.Host + r.URL.Path)
			http.Redirect(w, r, "https://auth.rival-afk.com/login?rd="+rd, http.StatusFound)
			return nil, false
		}
		writeErr(w, 401, "not logged in")
		return nil, false
	}
	if cap != "" && !hasCap(c, cap) {
		if html {
			http.Error(w, "403 — capability '"+cap+"' required", http.StatusForbidden)
			return nil, false
		}
		writeErr(w, 403, "capability '"+cap+"' required")
		return nil, false
	}
	return c, true
}

// ---- ed25519 challenge login ----

type webChallenge struct {
	pub string
	ts  time.Time
}

func (s *Server) challengeHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pubkey string `json:"pubkey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Pubkey) == "" {
		writeErr(w, 400, "pubkey required")
		return
	}
	pub := normalizePub(req.Pubkey)
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub)); err != nil {
		writeErr(w, 400, "bad pubkey")
		return
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM keys WHERE pubkey = ?`, pub).Scan(&n)
	if n == 0 {
		writeErr(w, 401, "unknown key")
		return
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	s.chMu.Lock()
	now := time.Now()
	for k, v := range s.chMap {
		if now.Sub(v.ts) > 5*time.Minute {
			delete(s.chMap, k)
		}
	}
	s.chMap[hex.EncodeToString(nonce)] = webChallenge{pub: pub, ts: now}
	s.chMu.Unlock()
	writeJSON(w, 200, map[string]string{"nonce": hex.EncodeToString(nonce)})
}

func (s *Server) webLoginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pubkey string `json:"pubkey"`
		Nonce  string `json:"nonce"`
		Sig    string `json:"sig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad request")
		return
	}
	pub := normalizePub(req.Pubkey)
	s.chMu.Lock()
	ch, ok := s.chMap[req.Nonce]
	delete(s.chMap, req.Nonce)
	s.chMu.Unlock()
	if !ok || ch.pub != pub || time.Since(ch.ts) > 5*time.Minute {
		writeErr(w, 401, "bad or expired challenge")
		return
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
	if err != nil {
		writeErr(w, 400, "bad pubkey")
		return
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Sig))
	if err != nil {
		writeErr(w, 400, "bad sig encoding")
		return
	}
	if !verifyEd25519Authorized(parsed, []byte("rival-web-v1|"+req.Nonce), sig) {
		writeErr(w, 401, "bad signature")
		return
	}
	var keyID, role, hostsJSON, label, capsJSON, userID string
	err = s.db.QueryRow(`SELECT id, role, hosts, label, caps, user_id FROM keys WHERE pubkey = ?`, pub).
		Scan(&keyID, &role, &hostsJSON, &label, &capsJSON, &userID)
	if err != nil {
		writeErr(w, 401, "unknown key")
		return
	}
	var hosts, caps []string
	json.Unmarshal([]byte(hostsJSON), &hosts)
	json.Unmarshal([]byte(capsJSON), &caps)
	if !containsStr(caps, "console") && !containsStr(caps, "ssh") {
		writeErr(w, 403, "no console access for this key")
		return
	}
	un := ""
	if userID != "" {
		s.db.QueryRow(`SELECT username FROM users WHERE id = ?`, userID).Scan(&un)
		if un == "" {
			// user deleted; drop orphan key link
			s.db.Exec(`UPDATE keys SET user_id = '' WHERE id = ?`, keyID)
		}
	}
	s.issueWebCookie(w, &Claims{KID: keyID, UN: un, Role: role, Hosts: hosts, Caps: caps})
	writeJSON(w, 200, map[string]interface{}{"ok": true, "label": label, "username": un, "caps": caps})
}

func (s *Server) webLogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: webCookie, Value: "", Path: "/", Domain: ".rival-afk.com", HttpOnly: true, Secure: true, MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusFound)
}

// ---- root@pc exec (service control + status) ----

func sshCombined(cl *ssh.Client, cmd string) ([]byte, error) {
	s, err := cl.NewSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.CombinedOutput(cmd)
}

func (s *Server) pcRootExec(cmd string) ([]byte, error) {
	key, err := os.ReadFile(s.cfg.Provisioner)
	if err != nil {
		return nil, fmt.Errorf("provisioner key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	cc := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	conn, err := net.DialTimeout("tcp", "10.66.0.2:22", 10*time.Second)
	if err != nil {
		return nil, err
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, "10.66.0.2:22", cc)
	if err != nil {
		return nil, err
	}
	cl := ssh.NewClient(sshConn, chans, reqs)
	defer cl.Close()
	return sshCombined(cl, cmd)
}

func (s *Server) consoleStatusHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireWebCap(w, r, "console", false); !ok {
		return
	}
	load, err := s.pcRootExec("cat /proc/loadavg; echo ---; awk '/MemTotal|MemAvailable/{print}' /proc/meminfo; echo ---; df -h / | tail -1; echo ---; rc-service mindustry status 2>&1 | head -2; echo ---; ss -uln | grep -q ':6567 ' && echo LISTEN_UDP || echo NO_UDP")
	parts := strings.Split(string(load), "---")
	get := func(i int) string {
		if i < len(parts) {
			return strings.TrimSpace(parts[i])
		}
		return ""
	}
	writeJSON(w, 200, map[string]interface{}{
		"load": get(0), "mem": get(1), "disk": get(2),
		"service": get(3), "udp": get(4), "ok": err == nil,
	})
}

func (s *Server) consoleServiceHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireWebCap(w, r, "console", false); !ok {
		return
	}
	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad request")
		return
	}
	if req.Action != "start" && req.Action != "stop" && req.Action != "restart" {
		writeErr(w, 400, "action must be start|stop|restart")
		return
	}
	out, err := s.pcRootExec("rc-service mindustry " + req.Action + " 2>&1")
	if err != nil {
		writeJSON(w, 500, map[string]interface{}{"ok": false, "error": strings.TrimSpace(string(out)) + " " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "out": strings.TrimSpace(string(out))})
}

// ---- mind@pc (chroot jail) ----

func (s *Server) mindSSHClient() (*ssh.Client, error) {
	key, err := os.ReadFile("/etc/rival/console_key")
	if err != nil {
		return nil, fmt.Errorf("console key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	cc := &ssh.ClientConfig{
		User:            "mind",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	conn, err := net.DialTimeout("tcp", "10.66.0.2:22", 10*time.Second)
	if err != nil {
		return nil, err
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, "10.66.0.2:22", cc)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

func (s *Server) mindExec(cmd string) ([]byte, error) {
	cl, err := s.mindSSHClient()
	if err != nil {
		return nil, err
	}
	defer cl.Close()
	return sshCombined(cl, cmd)
}

func safeName(n string) bool {
	if n == "" || len(n) > 128 || strings.Contains(n, "..") || strings.ContainsAny(n, "/\x00") {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func (s *Server) consoleFilesHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireWebCap(w, r, "console", false); !ok {
		return
	}
	kind := r.URL.Query().Get("kind")
	var dir string
	switch kind {
	case "plugins":
		dir = "config/plugins"
	case "maps":
		dir = "config/maps"
	default:
		writeErr(w, 400, "kind must be plugins or maps")
		return
	}
	out, err := s.mindExec("ls -la " + dir + " 2>&1 | tail -n +2")
	if err != nil {
		writeJSON(w, 500, map[string]interface{}{"ok": false, "error": strings.TrimSpace(string(out))})
		return
	}
	files := []map[string]interface{}{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) < 9 {
			continue
		}
		name := strings.Join(f[8:], " ")
		if name == "." || name == ".." {
			continue
		}
		files = append(files, map[string]interface{}{"name": name, "size": f[4], "perm": f[0]})
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "kind": kind, "dir": dir, "files": files})
}

var fetchMu sync.Mutex

func (s *Server) consoleFetchHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireWebCap(w, r, "console", false); !ok {
		return
	}
	var req struct {
		Kind string `json:"kind"`
		URL  string `json:"url"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad request")
		return
	}
	var dir, ext string
	switch req.Kind {
	case "plugins":
		dir, ext = "config/plugins", ".jar"
	case "maps":
		dir, ext = "config/maps", ".msav"
	default:
		writeErr(w, 400, "kind must be plugins or maps")
		return
	}
	u, err := url.Parse(req.URL)
	if err != nil || u.Scheme != "https" {
		writeErr(w, 400, "https url required")
		return
	}
	allowedHosts := map[string]bool{
		"github.com": true, "objects.githubusercontent.com": true,
		"raw.githubusercontent.com": true, "codeload.github.com": true,
		"gist.githubusercontent.com": true, "gitlab.com": true,
	}
	if !allowedHosts[strings.ToLower(u.Hostname())] {
		writeErr(w, 400, "host not allowed (github/gitlab only)")
		return
	}
	name := req.Name
	if name == "" {
		name = path.Base(u.Path)
	}
	if !safeName(name) {
		writeErr(w, 400, "bad file name")
		return
	}
	if !strings.HasSuffix(strings.ToLower(name), ext) {
		name += ext
	}

	fetchMu.Lock()
	defer fetchMu.Unlock()

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(req.URL)
	if err != nil {
		writeJSON(w, 502, map[string]interface{}{"ok": false, "error": "fetch: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		writeJSON(w, 502, map[string]interface{}{"ok": false, "error": "http " + strconv.Itoa(resp.StatusCode)})
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		writeJSON(w, 502, map[string]interface{}{"ok": false, "error": "read: " + err.Error()})
		return
	}
	if len(body) == 0 {
		writeJSON(w, 502, map[string]interface{}{"ok": false, "error": "empty file"})
		return
	}
	head := body
	if len(head) > 512 {
		head = head[:512]
	}
	if resp.Header.Get("Content-Type") == "text/html" && !bytes.Contains(head, []byte("PK")) {
		writeJSON(w, 502, map[string]interface{}{"ok": false, "error": "not a binary file (html page?)"})
		return
	}

	cl, err := s.mindSSHClient()
	if err != nil {
		writeJSON(w, 500, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	defer cl.Close()
	session, err := cl.NewSession()
	if err != nil {
		writeJSON(w, 500, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	defer session.Close()
	session.Stdin = bytes.NewReader(body)
	var stderr bytes.Buffer
	session.Stderr = &stderr
	target := dir + "/" + name
	if err := session.Start("cat > " + target); err != nil {
		writeJSON(w, 500, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	session.Wait()
	out, _ := s.mindExec("ls -la " + target + " 2>&1")
	if !strings.Contains(string(out), name) {
		writeJSON(w, 500, map[string]interface{}{"ok": false, "error": "upload failed: " + strings.TrimSpace(stderr.String()+" "+string(out))})
		return
	}
	log.Printf("console fetch: %s -> mind@pc:%s (%d bytes)", req.URL, target, len(body))
	writeJSON(w, 200, map[string]interface{}{"ok": true, "name": name, "size": len(body), "path": target, "note": "restart mindustry to apply"})
}

func (s *Server) consoleFileDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireWebCap(w, r, "console", false); !ok {
		return
	}
	kind := r.URL.Query().Get("kind")
	name := r.URL.Query().Get("name")
	var dir string
	switch kind {
	case "plugins":
		dir = "config/plugins"
	case "maps":
		dir = "config/maps"
	default:
		writeErr(w, 400, "bad kind")
		return
	}
	if !safeName(name) {
		writeErr(w, 400, "bad file name")
		return
	}
	out, err := s.mindExec("rm -f " + dir + "/" + name + " && echo deleted")
	if err != nil {
		writeJSON(w, 500, map[string]interface{}{"ok": false, "error": strings.TrimSpace(string(out))})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "deleted": name})
}

// ---- websocket ssh terminal ----

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type wsMsg struct {
	T    string `json:"t"`
	D    string `json:"d,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

func (s *Server) consoleWSHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireWebCap(w, r, "console", false); !ok {
		return
	}
	s.sshWS(w, r, "mind", "/etc/rival/console_key")
}

func (s *Server) consoleSSHHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireWebCap(w, r, "ssh", false); !ok {
		return
	}
	s.sshWS(w, r, "root", s.cfg.Provisioner)
}

func (s *Server) sshWS(w http.ResponseWriter, r *http.Request, user, keyPath string) {
	ws, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade: %v", err)
		return
	}
	defer ws.Close()

	send := func(m wsMsg) {
		ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
		ws.WriteJSON(m)
	}

	key, err := os.ReadFile(keyPath)
	if err != nil {
		send(wsMsg{T: "e", D: "key: " + err.Error()})
		return
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		send(wsMsg{T: "e", D: "key parse: " + err.Error()})
		return
	}
	cc := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	conn, err := net.DialTimeout("tcp", "10.66.0.2:22", 10*time.Second)
	if err != nil {
		send(wsMsg{T: "e", D: "dial pc: " + err.Error()})
		return
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, "10.66.0.2:22", cc)
	if err != nil {
		send(wsMsg{T: "e", D: "ssh: " + err.Error()})
		return
	}
	cl := ssh.NewClient(sshConn, chans, reqs)
	defer cl.Close()

	session, err := cl.NewSession()
	if err != nil {
		send(wsMsg{T: "e", D: "session: " + err.Error()})
		return
	}
	defer session.Close()

	stdout, _ := session.StdoutPipe()
	stdin, _ := session.StdinPipe()
	session.Stderr = session.Stdout

	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty("xterm-256color", 30, 100, modes); err != nil {
		send(wsMsg{T: "e", D: "pty: " + err.Error()})
		return
	}
	if err := session.Shell(); err != nil {
		send(wsMsg{T: "e", D: "shell: " + err.Error()})
		return
	}
	session.Start("")

	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if werr := ws.WriteJSON(wsMsg{T: "o", D: string(buf[:n])}); werr != nil {
					return
				}
			}
			if err != nil {
				send(wsMsg{T: "c"})
				session.Close()
				return
			}
		}
	}()

	for {
		var m wsMsg
		if err := ws.ReadJSON(&m); err != nil {
			session.Close()
			return
		}
		switch m.T {
		case "i":
			stdin.Write([]byte(m.D))
		case "r":
			if m.Cols > 0 && m.Rows > 0 && m.Cols < 500 && m.Rows < 300 {
				session.WindowChange(m.Rows, m.Cols)
			}
		}
	}
}

// ---- HTML pages (black & white, servera.sh style) ----

const bwCSS = `@font-face{font-family:Inter;font-style:normal;font-weight:400;font-display:swap;src:url(/console/inter-400.ttf) format('truetype')}
@font-face{font-family:Inter;font-style:normal;font-weight:500;font-display:swap;src:url(/console/inter-500.ttf) format('truetype')}
@font-face{font-family:Inter;font-style:normal;font-weight:700;font-display:swap;src:url(/console/inter-700.ttf) format('truetype')}
@font-face{font-family:Gasoek;font-style:normal;font-weight:400;font-display:swap;src:url(/console/gasoek.ttf) format('truetype')}
body{margin:0;padding:12px 16px;background:#000;color:#e8e8e8;font:14px/1.5 Inter,ui-monospace,Menlo,Consolas,monospace;touch-action:manipulation;-webkit-text-size-adjust:100%}
*{box-sizing:border-box}
a{color:#fff}a:hover{background:#fff;color:#000}
.box{border:1px solid #555;padding:10px 14px;margin:12px 0;overflow-wrap:break-word;word-break:break-word}
button,.btn{background:#000;color:#fff;border:1px solid #fff;padding:6px 16px;font:13px Inter,ui-monospace,monospace;cursor:pointer;text-decoration:none;display:inline-block;-webkit-appearance:none;appearance:none}
button:hover,.btn:hover{background:#fff;color:#000}
button:disabled{border-color:#555;color:#555;cursor:default}
input,textarea,select{background:#000;color:#fff;border:1px solid #555;padding:6px 8px;font:13px Inter,ui-monospace,monospace;-webkit-appearance:none;appearance:none;border-radius:0;max-width:100%}
input::placeholder,textarea::placeholder{color:#555}
input:focus,textarea:focus,select:focus{outline:none;border-color:#fff}
input[type=file]{background:#000;color:#888;border:1px solid #555;padding:4px 6px;font:12px Inter,ui-monospace,monospace;width:100%}
input[type=file]::file-selector-button{background:#000;color:#fff;border:1px solid #fff;padding:5px 14px;font:12px Inter,ui-monospace,monospace;cursor:pointer;margin-right:10px;-webkit-appearance:none;appearance:none}
input[type=file]::file-selector-button:hover{background:#fff;color:#000}
input[type=file]:hover{border-color:#888}
input[type=file]::-webkit-file-upload-button{background:#000;color:#fff;border:1px solid #fff;padding:5px 14px;font:12px Inter,ui-monospace,monospace;cursor:pointer;margin-right:10px;-webkit-appearance:none}
input[type=file]::-webkit-file-upload-button:hover{background:#fff;color:#000}
table{border-collapse:collapse;width:100%;table-layout:fixed}td,th{border:1px solid #444;padding:4px 10px;text-align:left;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:0}
td:nth-child(3),th:nth-child(3){white-space:normal;word-break:break-all}
.dim{color:#888}
.msg{border:1px solid #555;padding:6px 10px;margin:8px 0;min-height:1.2em;overflow-wrap:break-word;word-break:break-word}
.msg:empty:before{content:attr(data-ph);color:#555}
#term,#sterm{border:1px solid #555;padding:4px;height:420px;margin:10px 0;overflow:hidden}
pre{margin:0;overflow-x:auto}
.banner{font-family:Gasoek,ui-monospace,monospace;font-size:clamp(3px,1.1vw,13px);line-height:1.15;overflow:hidden;white-space:pre;margin:8px 0}
xterm{height:100%}
.xterm .xterm-viewport{background:#000!important}
.xterm-rows{font-family:ui-monospace,Menlo,Consolas,monospace!important}
.xterm{user-select:text;-webkit-user-select:text}
.xterm .xterm-screen{user-select:text;-webkit-user-select:text}`

func htmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

func (s *Server) loginPageHandler(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.Query().Get("rd")
	if rd == "" {
		rd = "https://mind.rival-afk.com/console"
	}
	if !strings.HasPrefix(rd, "https://") {
		rd = "https://mind.rival-afk.com/console"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := `<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover"><title>rival — login</title><style>` + bwCSS + `</style></head><body oncontextmenu="return false">
<pre class=banner> _   _   _ _____ _   _
| | | | | |_   _| | | |
| | | |_| | | | | |_| |
| | |  _  | | | |  _  |
| |_| | | | | | | | | |
 \___/|_| |_| |_| |_| |_|
</pre>
<div class=box style="max-width:560px">
<p><b>account</b></p>
<input id=un placeholder="username" autocomplete="username" style="width:100%">
<input id=pw type=password placeholder="password" autocomplete="current-password" style="width:100%">
<div class=msg id=msg data-ph="…"></div>
<button id=loginbtn>login</button>
<button id=regbtn>register</button>
<p class=dim>after login the browser generates an ed25519 key and stores it in
your secret storage (indexeddb) for one-click quick login. private key never
leaves the browser.</p>
<div id=quickbox style="display:none">
<button id=quickbtn>quick login</button>
<span class=dim id=quickinfo></span>
</div>
</div>
<div class=box style="max-width:560px;opacity:.65">
<p><b>or .rsh key</b> <span class=dim>(secondary)</span></p>
<p class=dim>select your private key file (~/.rsh/id):</p>
<input type=file id=kf style="width:100%">
<p class=dim>or paste public key, then sign with matching private key file above:</p>
<textarea id=pub rows=3 style="width:100%"></textarea>
<button id=kgo disabled>login with key</button>
</div>
<a class=btn href=/>back</a>
<input type=hidden id=rd value="` + htmlEsc(rd) + `">
<script>
// disable zoom: ctrl+wheel, pinch, double-tap
document.addEventListener('wheel',(e)=>{if(e.ctrlKey)e.preventDefault()},{passive:false});
document.addEventListener('touchstart',(e)=>{if(e.touches.length>1)e.preventDefault()},{passive:false});
let lastTouch=0;
document.addEventListener('touchend',(e)=>{
  const now=Date.now();
  if(now-lastTouch<=300){e.preventDefault()}
  lastTouch=now;
},{passive:false});
document.addEventListener('gesturestart',(e)=>e.preventDefault());
document.addEventListener('gesturechange',(e)=>e.preventDefault());
document.addEventListener('gestureend',(e)=>e.preventDefault());
document.addEventListener('keydown',(e)=>{
  if((e.ctrlKey||e.metaKey)&&(e.key==='='||e.key==='-'||e.key==='0'||e.code==='Equal'||e.code==='Minus'||e.code==='Digit0'))e.preventDefault();
});
const RD=document.getElementById('rd').value;
const msg=(t)=>document.getElementById('msg').textContent=t||'';
const b64=(buf)=>btoa(String.fromCharCode(...new Uint8Array(buf)));
const SSH_PREFIX=new Uint8Array([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);

// ---- secret storage (indexeddb) ----
const IDB_NAME='rival-web', IDB_STORE='keys';
function idb(){
  return new Promise((res,rej)=>{
    const q=indexedDB.open(IDB_NAME,1);
    q.onupgradeneeded=()=>{q.result.createObjectStore(IDB_STORE)};
    q.onsuccess=()=>res(q.result);
    q.onerror=()=>rej(q.error);
  });
}
async function idbGet(k){
  const db=await idb();
  return new Promise((res,rej)=>{
    const t=db.transaction(IDB_STORE,'readonly').objectStore(IDB_STORE).get(k);
    t.onsuccess=()=>res(t.result);t.onerror=()=>rej(t.error);
  });
}
async function idbPut(k,v){
  const db=await idb();
  return new Promise((res,rej)=>{
    const t=db.transaction(IDB_STORE,'readwrite').objectStore(IDB_STORE).put(v,k);
    t.onsuccess=()=>res();t.onerror=()=>rej(t.error);
  });
}
async function idbDel(k){
  const db=await idb();
  return new Promise((res,rej)=>{
    const t=db.transaction(IDB_STORE,'readwrite').objectStore(IDB_STORE).delete(k);
    t.onsuccess=()=>res();t.onerror=()=>rej(t.error);
  });
}

// ---- ed25519 helpers ----
async function generateBrowserKey(){
  const pair=await crypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);
  const pkcs8=new Uint8Array(await crypto.subtle.exportKey('pkcs8',pair.privateKey));
  const spki=new Uint8Array(await crypto.subtle.exportKey('spki',pair.publicKey));
  const rawPub=spki.slice(spki.length-32);
  const blob=new Uint8Array(4+11+4+32);
  const dv=new DataView(blob.buffer);
  dv.setUint32(0,11);blob.set(new TextEncoder().encode('ssh-ed25519'),4);
  dv.setUint32(15,32);blob.set(rawPub,19);
  const pubSsh='ssh-ed25519 '+btoa(String.fromCharCode(...blob));
  return {privPkcs8:pkcs8,pubSsh:pubSsh};
}
async function importStoredKey(rec){
  return crypto.subtle.importKey('pkcs8',rec.privPkcs8,{name:'Ed25519'},false,['sign']);
}
async function quickLoginFlow(rec){
  const privKey=await importStoredKey(rec);
  const ch=await (await fetch('/v1/web/challenge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pubkey:rec.pubSsh})})).json();
  if(ch.error){
    // stored key not on server anymore — drop it, ask for password login
    if(ch.error==='unknown key'){
      await idbDel('default');
      document.getElementById('quickbox').style.display='none';
      msg('stored key is not registered — login with password once to re-bind');
      return;
    }
    msg('challenge: '+ch.error);return;
  }
  const data=new TextEncoder().encode('rival-web-v1|'+ch.nonce);
  const sig=await crypto.subtle.sign({name:'Ed25519'},privKey,data);
  const res=await (await fetch('/v1/web/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pubkey:rec.pubSsh,nonce:ch.nonce,sig:b64(sig)})})).json();
  if(res.error){msg('login: '+res.error);return}
  location.href=RD;
}
async function bindBrowserKey(rec){
  const bn=await (await fetch('/v1/web/bindnonce',{method:'POST'})).json();
  if(bn.error)throw new Error(bn.error);
  const privKey=await importStoredKey(rec);
  const data=new TextEncoder().encode('rival-web-v1|'+bn.nonce);
  const sig=await crypto.subtle.sign({name:'Ed25519'},privKey,data);
  const bk=await (await fetch('/v1/web/bindkey',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pubkey:rec.pubSsh,nonce:bn.nonce,sig:b64(sig)})})).json();
  if(bk.error)throw new Error(bk.error);
  return bk;
}

// ---- password login / register ----
async function passLogin(isReg){
  const un=document.getElementById('un').value.trim().toLowerCase();
  const pw=document.getElementById('pw').value;
  if(!un||!pw){msg('username and password required');return}
  const url=isReg?'/v1/web/register':'/v1/web/passlogin';
  msg(isReg?'registering…':'logging in…');
  const res=await (await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:un,password:pw})})).json();
  if(res.error){msg(res.error);return}
  try{
    msg('generating browser key…');
    let rec=await idbGet('default');
    if(!rec||rec.user!==un){
      rec=await generateBrowserKey();
      rec.user=un;
      await idbPut('default',rec);
    }
    const bk=await bindBrowserKey(rec);
    msg('');
  }catch(e){msg('password login ok, but key bind failed: '+e.message);return}
  location.href=RD;
}
document.getElementById('loginbtn').onclick=()=>passLogin(false);
document.getElementById('regbtn').onclick=()=>passLogin(true);
document.getElementById('pw').addEventListener('keydown',(e)=>{if(e.key==='Enter')passLogin(false)});

// quick login button if a key is already stored
(async()=>{
  try{
    const rec=await idbGet('default');
    if(rec&&rec.pubSsh){
      document.getElementById('quickbox').style.display='block';
      document.getElementById('quickinfo').textContent=rec.user?('as '+rec.user):'';
      document.getElementById('quickbtn').onclick=async()=>{
        msg('quick login…');
        try{await quickLoginFlow(rec)}catch(e){msg('error: '+e.message)}
      };
    }
  }catch(e){/* no indexeddb — password only */}
})();

// ---- .rsh key file (secondary) ----
let privKey=null;
function parseOpenSSH(buf){
  const u=new Uint8Array(buf);
  const magic=new TextEncoder().encode('openssh-key-v1\0');
  for(let i=0;i<magic.length;i++)if(u[i]!==magic[i])return null;
  let off=magic.length;
  const dv=new DataView(u.buffer,u.byteOffset);
  const rdStr=()=>{const len=dv.getUint32(off);off+=4;const s=u.slice(off,off+len);off+=len;return s};
  rdStr();rdStr();rdStr();
  const nkeys=dv.getUint32(off);off+=4;
  if(nkeys!==1)return null;
  const pubLen=dv.getUint32(off);off+=4+pubLen;
  const privLen=dv.getUint32(off);off+=4;
  const priv=u.slice(off,off+privLen);
  const pdv=new DataView(priv.buffer,priv.byteOffset);
  let poff=8;
  const rdPStr=()=>{const len=pdv.getUint32(poff);poff+=4;const s=priv.slice(poff,poff+len);poff+=len;return s};
  const ktype=rdPStr();
  if(new TextDecoder().decode(ktype)!=='ssh-ed25519')throw new Error('only ed25519 supported');
  const pubRaw=rdPStr();
  const privRaw=rdPStr();
  if(pubRaw.length!==32||privRaw.length!==64)throw new Error('bad key len');
  return {seed:privRaw.slice(0,32),pubRaw:pubRaw};
}
async function importKeyFile(buf,name){
  try{
    const parsed=parseOpenSSH(buf);
    if(!parsed){msg('unrecognized key format — need openssh private key (~/.rsh/id)');return}
    const pkcs8=new Uint8Array(SSH_PREFIX.length+32);
    pkcs8.set(SSH_PREFIX,0);pkcs8.set(parsed.seed,SSH_PREFIX.length);
    privKey=await crypto.subtle.importKey('pkcs8',pkcs8,{name:'Ed25519'},false,['sign']);
    const blob=new Uint8Array(4+11+4+32);
    const dv=new DataView(blob.buffer);
    dv.setUint32(0,11);blob.set(new TextEncoder().encode('ssh-ed25519'),4);
    dv.setUint32(15,32);blob.set(parsed.pubRaw,19);
    document.getElementById('pub').value='ssh-ed25519 '+btoa(String.fromCharCode(...blob))+' browser';
    msg('key loaded: '+name+' — press login with key');
    document.getElementById('kgo').disabled=false;
  }catch(e){msg('error: '+e.message)}
}
document.getElementById('kf').addEventListener('change',async(e)=>{
  const f=e.target.files[0];if(!f)return;
  importKeyFile(await f.arrayBuffer(),f.name);
});
document.getElementById('kgo').onclick=async()=>{
  try{
    const pub='ssh-ed25519 '+document.getElementById('pub').value.replace(/^ssh-ed25519\s+/,'').trim();
    const ch=await (await fetch('/v1/web/challenge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pubkey:pub})})).json();
    if(ch.error){msg('challenge: '+ch.error);return}
    const data=new TextEncoder().encode('rival-web-v1|'+ch.nonce);
    const sig=await crypto.subtle.sign({name:'Ed25519'},privKey,data);
    const res=await (await fetch('/v1/web/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pubkey:pub,nonce:ch.nonce,sig:b64(sig)})})).json();
    if(res.error){msg('login: '+res.error);return}
    location.href=RD;
  }catch(e){msg('error: '+e.message)}
};
</script></body></html>`
	w.Write([]byte(page))
}

func (s *Server) consolePageHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireWebCap(w, r, "", true)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	label := claims.UN
	if label == "" {
		label = claims.KID
		s.db.QueryRow(`SELECT label FROM keys WHERE id = ?`, claims.KID).Scan(&label)
	}
	consoleUI := hasCap(claims, "console")
	sshUI := hasCap(claims, "ssh")

	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover"><title>rival — console</title><style>`)
	b.WriteString(bwCSS)
	b.WriteString(`</style><link rel=stylesheet href=/console/xterm.min.css></head><body oncontextmenu="return event.target.closest('.xterm')!==null">
<pre class=banner> ____ ___  _   _ ____   ___  _     _____
 / ___/ _ \| \ | / ___| / _ \| |   | ____|
| |  | | | |  \| \___ \| | | | |   |  _|
| |__| |_| | |\  |___) | |_| | |___| |___|
 \____\___/|_| \_|____/ \___/|_____|_____|
</pre>
<div class=box><b>mind console</b> — <b>`)
	b.WriteString(htmlEsc(label))
	b.WriteString(`</b> &middot; caps: <span class=dim>`)
	b.WriteString(htmlEsc(strings.Join(claims.Caps, ", ")))
	b.WriteString(`</span><a class=btn style="float:right" href=/v1/web/logout>logout</a></div>`)

	if consoleUI {
		b.WriteString(`<div class=box>
<b>service</b> <span id=svc class=dim>…</span>
<button onclick=svc('start')>start</button>
<button onclick=svc('stop')>stop</button>
<button onclick=svc('restart')>restart</button>
<span class=dim style="float:right" id=stat>…</span>
</div>
<div class=box>
<b>terminal</b> — mind@pc &middot; home=/home/mind (server dir, jailed)
<button onclick=connect() id=btn>connect</button>
<button onclick=disconnect() disabled id=dis>disconnect</button>
<div id=term></div>
</div>
<div class=box>
<b>plugins</b> <span class=dim>(config/plugins/*.jar)</span>
<div style="margin:8px 0">
<input id=purl size=50 placeholder="https://github.com/user/repo/releases/download/x/y.jar">
<button onclick=fetchFile('plugins')>fetch</button>
</div>
<table id=ptab><tr><th>perm</th><th>size</th><th>name</th><th></th></tr></table>
</div>
<div class=box>
<b>maps</b> <span class=dim>(config/maps/*.msav)</span>
<div style="margin:8px 0">
<input id=murl size=50 placeholder="https://github.com/user/repo/releases/download/x/map.msav">
<button onclick=fetchFile('maps')>fetch</button>
</div>
<table id=mtab><tr><th>perm</th><th>size</th><th>name</th><th></th></tr></table>
</div>`)
	}
	if sshUI {
		b.WriteString(`<div class=box>
<b>ssh root@pc</b> <span class=dim>(full root shell)</span>
<button onclick=sshConnect() id=sbtn>connect</button>
<button onclick=sshDisconnect() disabled id=sdis>disconnect</button>
<div id=sterm></div>
</div>`)
	}
	b.WriteString(`<div class=msg id=msg data-ph="…"></div>
<script src=/console/xterm.min.js></script>
<script src=/console/fit.min.js></script>
<script>
// disable zoom: ctrl+wheel, pinch, double-tap
document.addEventListener('wheel',(e)=>{if(e.ctrlKey)e.preventDefault()},{passive:false});
document.addEventListener('touchstart',(e)=>{if(e.touches.length>1)e.preventDefault()},{passive:false});
let lastTouch=0;
document.addEventListener('touchend',(e)=>{
  const now=Date.now();
  if(now-lastTouch<=300){e.preventDefault()}
  lastTouch=now;
},{passive:false});
document.addEventListener('gesturestart',(e)=>e.preventDefault());
document.addEventListener('gesturechange',(e)=>e.preventDefault());
document.addEventListener('gestureend',(e)=>e.preventDefault());
document.addEventListener('keydown',(e)=>{
  if((e.ctrlKey||e.metaKey)&&(e.key==='='||e.key==='-'||e.key==='0'||e.code==='Equal'||e.code==='Minus'||e.code==='Digit0'))e.preventDefault();
});
const msg=(t)=>{const e=document.getElementById('msg');if(e)e.textContent=t||''};
async function j(u,b){const r=await fetch(u,b?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}:{});return r.json()}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}`)

	if consoleUI {
		b.WriteString(`
async function refresh(){
  const s=await j('/v1/console/status');
  if(s.error){document.getElementById('stat').textContent='err: '+s.error;return}
  document.getElementById('stat').textContent='load '+(s.load||'?')+' | '+(s.mem||'')+' | '+(s.disk||'');
  document.getElementById('svc').textContent=((s.service||'').includes('started')?'started':(s.service||'').includes('stopped')?'stopped':'?')+(s.udp==='LISTEN_UDP'?' udp:6567':' udp:down');
}
async function svc(a){msg('service '+a+'…');const r=await j('/v1/console/service',{action:a});msg(r.ok?('service '+a+' ok'):('service: '+(r.error||'fail')));setTimeout(refresh,1500)}
async function ls(kind,tab){
  const r=await j('/v1/console/files?kind='+kind);
  const t=document.getElementById(tab);
  while(t.rows.length>1)t.deleteRow(1);
  if(r.error){msg(r.error);return}
  for(const f of r.files||[]){
    const row=t.insertRow();
    row.innerHTML='<td class=dim>'+esc(f.perm)+'</td><td class=dim>'+esc(f.size)+'</td><td>'+esc(f.name)+'</td><td><button onclick="del(\''+kind+'\',\''+esc(f.name)+'\')">x</button></td>';
  }
}
async function del(kind,name){if(!confirm('delete '+name+'?'))return;msg('deleting '+name);await fetch('/v1/console/file?kind='+kind+'&name='+encodeURIComponent(name),{method:'DELETE'});ls(kind,kind==='plugins'?'ptab':'mtab')}
async function fetchFile(kind){
  const inp=document.getElementById(kind==='plugins'?'purl':'murl');
  msg('fetching '+inp.value+' …');
  const r=await j('/v1/console/fetch',{kind:kind,url:inp.value});
  msg(r.ok?('saved '+r.name+' ('+r.size+' bytes) — '+r.note):('fetch: '+(r.error||'fail')));
  if(r.ok){inp.value='';ls(kind,kind==='plugins'?'ptab':'mtab')}
}
let term,fit,ws;
function connect(){
  term=new Terminal({cursorBlink:true,theme:{background:'#000',foreground:'#e8e8e8'},fontSize:13,fontFamily:'monospace'});
  fit=new FitAddon.FitAddon();term.loadAddon(fit);term.open(document.getElementById('term'));fit.fit();
  term.writeln('connecting mind@pc ...');
  const proto=location.protocol==='https:'?'wss':'ws';
  ws=new WebSocket(proto+'://'+location.host+'/console/ws');
  ws.onopen=()=>{ws.send(JSON.stringify({t:'r',cols:term.cols,rows:term.rows}));document.getElementById('btn').disabled=true;document.getElementById('dis').disabled=false;term.focus()};
  ws.onmessage=(e)=>{const m=JSON.parse(e.data);if(m.t==='o')term.write(m.d);else if(m.t==='e')term.writeln('\r\n[error] '+m.d);else if(m.t==='c')term.writeln('\r\n[disconnected]')};
  ws.onclose=()=>{document.getElementById('btn').disabled=false;document.getElementById('dis').disabled=true};
  term.onData((d)=>{if(ws&&ws.readyState===1)ws.send(JSON.stringify({t:'i',d:d}))});
  window.addEventListener('resize',()=>{fit.fit();if(ws&&ws.readyState===1)ws.send(JSON.stringify({t:'r',cols:term.cols,rows:term.rows}))});
}
function disconnect(){if(ws)ws.close()}`)
	}
	if sshUI {
		b.WriteString(`
let ster,sfit,sws;
function sshConnect(){
  ster=new Terminal({cursorBlink:true,theme:{background:'#000',foreground:'#e8e8e8'},fontSize:13,fontFamily:'monospace'});
  sfit=new FitAddon.FitAddon();ster.loadAddon(sfit);ster.open(document.getElementById('sterm'));sfit.fit();
  ster.writeln('connecting root@pc ...');
  const proto=location.protocol==='https:'?'wss':'ws';
  sws=new WebSocket(proto+'://'+location.host+'/console/ssh');
  sws.onopen=()=>{sws.send(JSON.stringify({t:'r',cols:ster.cols,rows:ster.rows}));document.getElementById('sbtn').disabled=true;document.getElementById('sdis').disabled=false;ster.focus()};
  sws.onmessage=(e)=>{const m=JSON.parse(e.data);if(m.t==='o')ster.write(m.d);else if(m.t==='e')ster.writeln('\r\n[error] '+m.d);else if(m.t==='c')ster.writeln('\r\n[disconnected]')};
  sws.onclose=()=>{document.getElementById('sbtn').disabled=false;document.getElementById('sdis').disabled=true};
  ster.onData((d)=>{if(sws&&sws.readyState===1)sws.send(JSON.stringify({t:'i',d:d}))});
  window.addEventListener('resize',()=>{sfit.fit();if(sws&&sws.readyState===1)sws.send(JSON.stringify({t:'r',cols:ster.cols,rows:ster.rows}))});
}
function sshDisconnect(){if(sws)sws.close()}`)
	}
	if consoleUI {
		b.WriteString(`
refresh();setInterval(refresh,5000);ls('plugins','ptab');ls('maps','mtab')`)
	}
	b.WriteString(`
</script></body></html>`)
	w.Write([]byte(b.String()))
}

// ---- static xterm assets ----

func (s *Server) consoleStaticHandler(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/console/")
	if name == "" {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("web/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	if strings.HasSuffix(name, ".css") {
		w.Header().Set("Content-Type", "text/css")
	} else if strings.HasSuffix(name, ".js") {
		w.Header().Set("Content-Type", "application/javascript")
	} else if strings.HasSuffix(name, ".ttf") {
		w.Header().Set("Content-Type", "font/ttf")
	}
	w.Write(data)
}

// ---- error page ----

func (s *Server) errorPageHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		code = "unknown"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	page := `<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"><title>rival — error</title><style>` + bwCSS + `
.center{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:80vh;text-align:center}
.code{font-size:64px;font-weight:bold;margin:0}
.msg-big{font-size:18px;margin-top:12px}
.sub{margin-top:20px}
</style></head><body oncontextmenu="return false">
<div class=center>
<pre class=banner style="font-size:clamp(3px,1.1vw,11px)"> __  __ ___ _   _ ____  _   _ ____ _____ ______   __
|  \/  |_ _| \ | |  _ \| | | / ___|_   _|  _ \ \ / /
| |\/| || ||  \| | | | | | | \___ \ | | | |_) \ V /
| |  | || || |\  | |_| | |_| |___) || | |  _ < | |
|_|  |_|___|_| \_|____/ \___/|____/ |_| |_| \_\|_|
</pre>
<p class=code>` + htmlEsc(code) + `</p>
<p class=msg-big>Ой... что-то сломалось</p>
<p class=sub><a class=btn href=/>на главную</a></p>
</div>
<script>
document.addEventListener('wheel',(e)=>{if(e.ctrlKey)e.preventDefault()},{passive:false});
document.addEventListener('touchstart',(e)=>{if(e.touches.length>1)e.preventDefault()},{passive:false});
document.addEventListener('gesturestart',(e)=>e.preventDefault());
</script></body></html>`
	w.Write([]byte(page))
}
