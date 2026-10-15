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
	var keyID, role, hostsJSON, label, capsJSON string
	err = s.db.QueryRow(`SELECT id, role, hosts, label, caps FROM keys WHERE pubkey = ?`, pub).
		Scan(&keyID, &role, &hostsJSON, &label, &capsJSON)
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
	s.issueWebCookie(w, &Claims{KID: keyID, Role: role, Hosts: hosts, Caps: caps})
	writeJSON(w, 200, map[string]interface{}{"ok": true, "label": label, "caps": caps})
}

func (s *Server) webLogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: webCookie, Value: "", Path: "/", HttpOnly: true, Secure: true, MaxAge: -1})
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

const bwCSS = `body{margin:0;background:#000;color:#e8e8e8;font:14px/1.5 ui-monospace,Menlo,Consolas,monospace}
a{color:#fff}a:hover{background:#fff;color:#000}
.box{border:1px solid #555;padding:10px 14px;margin:12px 0}
button,.btn{background:#000;color:#fff;border:1px solid #fff;padding:6px 16px;font:13px ui-monospace,monospace;cursor:pointer;text-decoration:none;display:inline-block}
button:hover,.btn:hover{background:#fff;color:#000}
button:disabled{border-color:#555;color:#555;cursor:default}
input,textarea{background:#000;color:#fff;border:1px solid #555;padding:6px 8px;font:13px ui-monospace,monospace}
input:focus,textarea:focus{outline:none;border-color:#fff}
table{border-collapse:collapse;width:100%%}td,th{border:1px solid #444;padding:4px 10px;text-align:left}
.dim{color:#888}
.msg{border:1px solid #555;padding:6px 10px;margin:8px 0;min-height:1.2em}
#term,#sterm{border:1px solid #555;padding:4px;height:420px;margin:10px 0}`

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
	page := `<!doctype html><html><head><meta charset=utf-8><title>rival — login</title><style>` + bwCSS + `</style></head><body>
<pre>
██████╗ ██╗   ██╗██╗███╗   ██╗
██╔══██╗╚██╗ ██╔╝██║████╗  ██║
██████╔╝ ╚████╔╝ ██║██╔██╗ ██║
██╔══██╗  ╚██╔╝  ██║██║╚██╗██║
██║  ██║   ██║   ██║██║ ╚████║
╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝  ╚═══╝
</pre>
<div class=box style="max-width:560px">
<p><b>console login</b></p>
<p class=dim>sign a one-time nonce with your registered ed25519 key.
your private key never leaves the browser (webcrypto).</p>
<p class=dim>select your private key file (~/.rsh/id):</p>
<input type=file id=kf style="width:100%">
<p class=dim>or paste public key, then sign with matching private key file above:</p>
<textarea id=pub rows=3 style="width:100%"></textarea>
<div class=msg id=msg>select your private key file (~/.rsh/id)</div>
<button id=go disabled>login</button>
<a class=btn href=/>back</a>
</div>
<input type=hidden id=rd value="` + htmlEsc(rd) + `">
<script>
const msg=(t)=>document.getElementById('msg').textContent=t;
let privKey=null;
const b64=(buf)=>btoa(String.fromCharCode(...new Uint8Array(buf)));
function parseOpenSSH(buf){
  const u=new Uint8Array(buf);
  const magic=new TextEncoder().encode('openssh-key-v1\0');
  for(let i=0;i<magic.length;i++)if(u[i]!==magic[i])return null;
  let off=magic.length;
  const dv=new DataView(u.buffer,u.byteOffset);
  const rdStr=()=>{const len=dv.getUint32(off);off+=4;const s=u.slice(off,off+len);off+=len;return s};
  rdStr();rdStr();rdStr(); // cipher, kdf, kdf options
  const nkeys=dv.getUint32(off);off+=4;
  if(nkeys!==1)return null;
  const pubLen=dv.getUint32(off);off+=4+pubLen;
  const privLen=dv.getUint32(off);off+=4;
  const priv=u.slice(off,off+privLen);
  const pdv=new DataView(priv.buffer,priv.byteOffset);
  let poff=8; // checkint x2
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
    const text=new TextDecoder().decode(buf.slice(0,200));
    if(text.includes('BEGIN')&&text.includes('PRIVATE KEY')){msg('use openssh format (~/.rsh/id), not PEM');return}
    if(!text.includes('openssh-key-v1')&&!buf.includes){/* binary check below */}
    const parsed=parseOpenSSH(buf);
    if(!parsed){msg('unrecognized key format — need openssh private key (~/.rsh/id)');return}
    const prefix=new Uint8Array([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
    const pkcs8=new Uint8Array(prefix.length+32);
    pkcs8.set(prefix,0);pkcs8.set(parsed.seed,prefix.length);
    privKey=await crypto.subtle.importKey('pkcs8',pkcs8,{name:'Ed25519'},false,['sign']);
    const blob=new Uint8Array(4+11+4+32);
    const dv=new DataView(blob.buffer);
    dv.setUint32(0,11);blob.set(new TextEncoder().encode('ssh-ed25519'),4);
    dv.setUint32(15,32);blob.set(parsed.pubRaw,19);
    document.getElementById('pub').value='ssh-ed25519 '+btoa(String.fromCharCode(...blob))+' browser';
    msg('key loaded: '+name+' — press login');
    document.getElementById('go').disabled=false;
  }catch(e){msg('error: '+e.message)}
}
document.getElementById('kf').addEventListener('change',async(e)=>{
  const f=e.target.files[0];if(!f)return;
  importKeyFile(await f.arrayBuffer(),f.name);
});
document.getElementById('go').onclick=async()=>{
  try{
    const pub='ssh-ed25519 '+document.getElementById('pub').value.replace(/^ssh-ed25519\s+/,'').trim();
    const ch=await (await fetch('/v1/web/challenge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pubkey:pub})})).json();
    if(ch.error){msg('challenge: '+ch.error);return}
    const data=new TextEncoder().encode('rival-web-v1|'+ch.nonce);
    const sig=await crypto.subtle.sign({name:'Ed25519'},privKey,data);
    const res=await (await fetch('/v1/web/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pubkey:pub,nonce:ch.nonce,sig:b64(sig)})})).json();
    if(res.error){msg('login: '+res.error);return}
    location.href=document.getElementById('rd').value;
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
	label := claims.KID
	s.db.QueryRow(`SELECT label FROM keys WHERE id = ?`, claims.KID).Scan(&label)
	consoleUI := hasCap(claims, "console")
	sshUI := hasCap(claims, "ssh")

	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset=utf-8><title>rival — console</title><style>`)
	b.WriteString(bwCSS)
	b.WriteString(`</style><link rel=stylesheet href=/console/xterm.min.css></head><body>
<pre>
█ ███ █ █   █ ███▀▀ █ █ █▀▀
█  █  █ █   █ █▀▀  █   █▀▀
█▄▄█ ▄█ █ █ █▄█▄▄ █▄█ █▄▄
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
	b.WriteString(`<div class=msg id=msg></div>
<script src=/console/xterm.min.js></script>
<script src=/console/fit.min.js></script>
<script>
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
	}
	w.Write(data)
}
