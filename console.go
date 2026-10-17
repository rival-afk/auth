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
	raw, err := s.pcRootExec("cat /proc/loadavg; echo ---; awk '/MemTotal|MemAvailable/{print $2}' /proc/meminfo; echo ---; df -h / | tail -1 | awk '{print $5, $4}'; echo ---; rc-service mindustry status 2>&1 | head -1; echo ---; ss -uln | grep -q ':6567 ' && echo up || echo down")
	parts := strings.Split(string(raw), "---")
	get := func(i int) string {
		if i < len(parts) {
			return strings.TrimSpace(parts[i])
		}
		return ""
	}
	// parse loadavg -> "0.69 0.54 0.54"
	loadStr := get(0)
	if f := strings.Fields(loadStr); len(f) >= 3 {
		loadStr = f[0] + " " + f[1] + " " + f[2]
	}
	// parse meminfo (kB) -> "1.6 / 31.2 GB"
	memStr := get(1)
	if f := strings.Fields(memStr); len(f) >= 2 {
		if totalKB, err1 := strconv.ParseFloat(f[0], 64); err1 == nil {
			if availKB, err2 := strconv.ParseFloat(f[1], 64); err2 == nil {
				totalGB := totalKB / 1048576
				usedGB := (totalKB - availKB) / 1048576
				memStr = fmt.Sprintf("%.1f/%.1f GB", usedGB, totalGB)
			}
		}
	}
	// parse disk -> Use% Avail -> "44.8G free (3%)"
	diskStr := get(2)
	if f := strings.Fields(diskStr); len(f) >= 2 {
		diskStr = f[1] + " free (" + f[0] + ")"
	}
	// service status -> just started/stopped
	svc := get(3)
	if strings.Contains(svc, "started") {
		svc = "started"
	} else if strings.Contains(svc, "stopped") {
		svc = "stopped"
	} else {
		svc = "unknown"
	}
	udp := get(4)
	writeJSON(w, 200, map[string]interface{}{
		"load": loadStr, "mem": memStr, "disk": diskStr,
		"service": svc, "udp": udp, "ok": err == nil,
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

// ---- link resolution: GitHub/GitLab page links -> direct file links ----

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}
type ghTree struct {
	Tree []struct {
		Path string `json:"path"`
		Type string `json:"type"`
	} `json:"tree"`
}

func httpGetJSON(rawURL string, v interface{}) error {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "rival-auth")
	req.Header.Set("Accept", "application/vnd.github+json, application/json")
	cl := &http.Client{Timeout: 30 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(v)
}

func assetMatches(name, ext string) bool {
	ln := strings.ToLower(name)
	if !strings.HasSuffix(ln, ext) {
		return false
	}
	for _, bad := range []string{"source", "javadoc", "sha256", ".asc", ".sig"} {
		if strings.Contains(ln, bad) {
			return false
		}
	}
	return true
}

func githubReleaseAsset(owner, repo, tag, ext string) (string, string, error) {
	api := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	if tag != "" {
		api = fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", owner, repo, url.PathEscape(tag))
	}
	var rel ghRelease
	if err := httpGetJSON(api, &rel); err != nil {
		return "", "", fmt.Errorf("не удалось получить релизы GitHub (%v)", err)
	}
	for _, a := range rel.Assets {
		if assetMatches(a.Name, ext) {
			return a.URL, a.Name, nil
		}
	}
	for _, a := range rel.Assets {
		if strings.HasSuffix(strings.ToLower(a.Name), ext) {
			return a.URL, a.Name, nil
		}
	}
	if len(rel.Assets) > 0 {
		var names []string
		for _, a := range rel.Assets {
			names = append(names, a.Name)
		}
		return "", "", fmt.Errorf("в релизе %s нет файла %s (доступно: %s)", rel.TagName, ext, strings.Join(names, ", "))
	}
	return "", "", fmt.Errorf("у этого репозитория нет релизов — откройте Releases и скопируйте ссылку на файл %s", ext)
}

func githubRepoFile(owner, repo, ext string) (string, string, error) {
	api := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/trees/HEAD?recursive=1", owner, repo)
	var tr ghTree
	if err := httpGetJSON(api, &tr); err != nil {
		return "", "", fmt.Errorf("не удалось прочитать файлы репозитория (%v)", err)
	}
	for _, t := range tr.Tree {
		if t.Type == "blob" && strings.HasSuffix(strings.ToLower(t.Path), ext) {
			raw := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/HEAD/%s", owner, repo, t.Path)
			return raw, path.Base(t.Path), nil
		}
	}
	return "", "", fmt.Errorf("в репозитории не найден файл %s — откройте Releases и скопируйте прямую ссылку", ext)
}

// resolveFetchURL turns a user-supplied link into a direct downloadable file URL.
// Direct links pass through; repo/release pages are resolved via the GitHub API.
func resolveFetchURL(raw, ext string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("не удалось разобрать ссылку")
	}
	switch strings.ToLower(u.Hostname()) {
	case "raw.githubusercontent.com", "objects.githubusercontent.com", "codeload.github.com", "gist.githubusercontent.com", "gitlab.com":
		return raw, path.Base(u.Path), nil
	case "github.com":
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) < 2 {
			return "", "", fmt.Errorf("ссылка должна вести на репозиторий, релиз или файл")
		}
		owner, repo := parts[0], parts[1]
		if len(parts) >= 5 && parts[2] == "releases" && parts[3] == "download" {
			return raw, path.Base(u.Path), nil
		}
		if len(parts) >= 5 && parts[2] == "releases" && parts[3] == "tag" {
			if dl, nm, e := githubReleaseAsset(owner, repo, parts[4], ext); e == nil {
				return dl, nm, nil
			}
			return githubRepoFile(owner, repo, ext)
		}
		if dl, nm, e := githubReleaseAsset(owner, repo, "", ext); e == nil {
			return dl, nm, nil
		}
		return githubRepoFile(owner, repo, ext)
	}
	return "", "", fmt.Errorf("неподдерживаемая ссылка")
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
		writeErr(w, 400, "нужна ссылка https://…")
		return
	}
	allowedHosts := map[string]bool{
		"github.com": true, "objects.githubusercontent.com": true,
		"raw.githubusercontent.com": true, "codeload.github.com": true,
		"gist.githubusercontent.com": true, "gitlab.com": true,
	}
	if !allowedHosts[strings.ToLower(u.Hostname())] {
		writeErr(w, 400, "поддерживаются только ссылки GitHub/GitLab")
		return
	}
	// GitHub/GitLab *page* links (repo, releases, tag) are HTML — resolve them
	// to a direct asset/file link for the requested extension.
	dlURL, resolvedName, rerr := resolveFetchURL(req.URL, ext)
	if rerr != nil {
		writeJSON(w, 502, map[string]interface{}{"ok": false, "error": rerr.Error()})
		return
	}
	name := req.Name
	if name == "" {
		name = resolvedName
	}
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
	resp, err := client.Get(dlURL)
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
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") && !bytes.Contains(head, []byte("PK")) {
		writeJSON(w, 502, map[string]interface{}{"ok": false, "error": "это HTML-страница, а не файл — нужна прямая ссылка на " + ext + " (обычно: Releases → Assets)"})
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
	if err := session.Start("mkdir -p " + dir + " && cat > " + target); err != nil {
		writeJSON(w, 500, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	if err := session.Wait(); err != nil {
		writeJSON(w, 500, map[string]interface{}{"ok": false, "error": "upload failed: " + strings.TrimSpace(stderr.String()+" "+err.Error())})
		return
	}
	szOut, _ := s.mindExec("wc -c < " + target + " 2>/dev/null")
	got, _ := strconv.Atoi(strings.TrimSpace(string(szOut)))
	if got != len(body) {
		writeJSON(w, 500, map[string]interface{}{"ok": false, "error": fmt.Sprintf("upload failed: %d of %d bytes", got, len(body))})
		return
	}
	log.Printf("console fetch: %s -> mind@pc:%s (%d bytes)", dlURL, target, len(body))
	writeJSON(w, 200, map[string]interface{}{"ok": true, "name": name, "size": len(body), "path": target, "note": "перезапустите сервер, чтобы применить"})
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
@font-face{font-family:'JetBrains Mono';font-style:normal;font-weight:400;font-display:swap;src:url(/console/jbmono-400.ttf) format('truetype')}
@font-face{font-family:'JetBrains Mono';font-style:normal;font-weight:500;font-display:swap;src:url(/console/jbmono-500.ttf) format('truetype')}
body{margin:0;padding:12px 16px;background:var(--surface);color:var(--on-surface);font:14px/1.55 Inter,system-ui,Menlo,Consolas,monospace;touch-action:manipulation;-webkit-text-size-adjust:100%}
*{box-sizing:border-box}
:root{--ease:cubic-bezier(.4,0,.2,1);--ease-em:cubic-bezier(.05,.7,.1,1);--dur:250ms;--dur-l:420ms;--primary:#ff3355;--on-primary:#4a0011;--surface:#16181d;--surface-c:#1d2024;--surface-ch:#262a2f;--outline:#44464f;--on-surface:#e2e2e9;--on-surface-variant:#c6c6d0;--muted:#8f9099}
@keyframes m3-enter{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
@keyframes m3-scale{from{opacity:0;transform:scale(.94)}to{opacity:1;transform:none}}
button,.btn,input,textarea,select,a{transition:background-color var(--dur) var(--ease),color var(--dur) var(--ease),border-color var(--dur) var(--ease),box-shadow var(--dur) var(--ease),transform var(--dur) var(--ease-em),opacity var(--dur) var(--ease)}
:focus-visible{outline:3px solid var(--primary);outline-offset:2px}
@media (prefers-reduced-motion:reduce){*{animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important}}
a{color:var(--primary)}a:hover{background:var(--primary);color:var(--on-primary)}
.box{border:1px solid var(--outline);background:var(--surface-c);border-radius:16px;padding:10px 14px;margin:12px 0;overflow-wrap:break-word;word-break:break-word}
button,.btn{background:transparent;color:var(--primary);border:1px solid var(--outline);border-radius:999px;padding:7px 18px;font:500 13px Inter,system-ui,monospace;cursor:pointer;text-decoration:none;display:inline-block;-webkit-appearance:none;appearance:none}
button:hover,.btn:hover{background:rgba(255,51,85,.12);border-color:var(--primary)}
button:active,.btn:active{transform:scale(.97)}
button:disabled{border-color:var(--outline);color:#6b6d76;cursor:default}
button:disabled:hover{background:transparent;border-color:var(--outline)}
input,textarea,select{background:var(--surface);color:var(--on-surface);border:1px solid var(--outline);border-radius:10px;padding:8px 10px;font:13px Inter,system-ui,monospace;-webkit-appearance:none;appearance:none;max-width:100%}
input::placeholder,textarea::placeholder{color:#6b6d76}
input:focus,textarea:focus,select:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(255,51,85,.16)}
input[type=file]{padding:4px 6px;color:var(--muted);font-size:12px;width:100%}
input[type=file]::file-selector-button{background:transparent;color:var(--primary);border:1px solid var(--outline);border-radius:999px;padding:5px 14px;font:12px Inter,system-ui,monospace;cursor:pointer;margin-right:10px;-webkit-appearance:none;appearance:none}
input[type=file]::file-selector-button:hover{background:rgba(255,51,85,.12);border-color:var(--primary)}
input[type=file]:hover{border-color:var(--muted)}
input[type=file]::-webkit-file-upload-button{background:transparent;color:var(--primary);border:1px solid var(--outline);border-radius:999px;padding:5px 14px;font:12px Inter,system-ui,monospace;cursor:pointer;margin-right:10px;-webkit-appearance:none}
input[type=file]::-webkit-file-upload-button:hover{background:rgba(255,51,85,.12);border-color:var(--primary)}
table{border-collapse:collapse;width:100%;table-layout:fixed}td,th{border:1px solid #2f323a;padding:4px 10px;text-align:left;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:0}
td:nth-child(3),th:nth-child(3){white-space:normal;word-break:break-all}
.dim{color:var(--muted);font-family:'JetBrains Mono',ui-monospace,monospace;font-size:12px}
.stat{font-family:'JetBrains Mono',ui-monospace,monospace;font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;display:inline-block;vertical-align:middle}
.msg{border:1px solid var(--outline);background:var(--surface-c);border-radius:12px;padding:8px 12px;margin:10px 0;min-height:1.2em;overflow-wrap:break-word;word-break:break-word}
.msg:empty:before{content:attr(data-ph);color:#6b6d76}
#term,#sterm{border:1px solid var(--outline);background:#0b0d11;border-radius:16px;padding:4px;height:420px;margin:10px 0;overflow:hidden}
pre{margin:0;overflow-x:auto}
.banner{font-family:Inter,system-ui,sans-serif;font-weight:700;font-size:clamp(30px,9vw,56px);line-height:1.05;letter-spacing:-.02em;margin:16px 0 18px;overflow-wrap:break-word}
xterm{height:100%}
.xterm .xterm-viewport{background:#000!important}
.xterm-rows{font-family:ui-monospace,Menlo,Consolas,monospace!important}
.xterm{user-select:text;-webkit-user-select:text}
.xterm .xterm-screen{user-select:text;-webkit-user-select:text}`

const loginCSS = `
body{padding:0}
main.page{min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:28px 16px}
.card{width:100%;max-width:560px;animation:m3-enter var(--dur-l) var(--ease-em) both}
.head{text-align:center;margin:0 0 22px}
.banner{font-size:clamp(34px,11vw,58px);letter-spacing:-.02em;margin:0}
.sub{color:var(--muted);font-family:'JetBrains Mono',ui-monospace,monospace;font-size:12px;letter-spacing:.02em;margin:10px 0 0}
.panel{border:1px solid rgba(68,70,79,.7);background:var(--surface-c);border-radius:28px;padding:20px 22px;margin:0 0 14px;box-shadow:0 1px 2px rgba(0,0,0,.35);animation:m3-enter var(--dur-l) var(--ease-em) both}
.panel:nth-of-type(2){animation-delay:.05s}
.panel:nth-of-type(3){animation-delay:.1s}
.panel.muted{opacity:.9;background:var(--surface)}
.panel-title{font:500 11px 'JetBrains Mono',ui-monospace,monospace;text-transform:uppercase;letter-spacing:.14em;color:var(--on-surface-variant);margin:0 0 6px}
.field{display:block;font:400 11px 'JetBrains Mono',ui-monospace,monospace;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin:14px 0 6px}
.panel input,.panel textarea{width:100%;padding:10px 12px;font-size:14px;border-radius:12px}
.panel p.dim{margin:12px 0 0}
.msg{margin:14px 0 0}
.msg:empty{border-color:transparent;background:transparent;padding:0;min-height:0}
.actions{display:flex;gap:10px;margin-top:16px}
.actions button{flex:1;padding:11px 16px;font-size:13.5px}
button.primary{background:var(--primary);color:var(--on-primary);border-color:transparent;font-weight:600;box-shadow:0 1px 2px rgba(0,0,0,.35)}
button.primary:hover{background:var(--primary);color:var(--on-primary);opacity:.9;box-shadow:0 4px 8px 3px rgba(0,0,0,.2)}
.quick{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:12px}
.foot{text-align:center;margin:18px 0 0}
.foot .btn{padding:8px 20px}
@media (max-height:620px){main.page{align-items:flex-start}}
`

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
	w.Header().Set("Cache-Control", "no-store")
	page := `<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover"><title>rival — login</title><style>` + bwCSS + loginCSS + `</style></head><body oncontextmenu="return false">
<main class=page>
<div class=card>
<div class=head>
<div class=banner>rival</div>
<p class=sub>sign in to your account</p>
</div>
<section class=panel>
<div class=panel-title>account</div>
<label class=field for=un>username</label>
<input id=un placeholder="username" autocomplete="username">
<label class=field for=pw>password</label>
<input id=pw type=password placeholder="password" autocomplete="current-password">
<div class=msg id=msg data-ph="…"></div>
<div class=actions>
<button id=loginbtn class=primary>login</button>
<button id=regbtn>register</button>
</div>
<p class=dim>after login the browser generates an ed25519 key and stores it in
your secret storage (indexeddb) for one-click quick login. private key never
leaves the browser.</p>
<div id=quickbox class=quick style="display:none">
<button id=quickbtn>quick login</button>
<span class=dim id=quickinfo></span>
</div>
</section>
<section class="panel muted">
<div class=panel-title>or .rsh key <span class=dim>(secondary)</span></div>
<p class=dim>select your private key file (~/.rsh/id):</p>
<input type=file id=kf>
<p class=dim>or paste public key, then sign with matching private key file above:</p>
<textarea id=pub rows=3></textarea>
<button id=kgo disabled>login with key</button>
</section>
<div class=foot><a class=btn href=/>← back</a></div>
</div>
</main>
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
  if(isReg){msg(res.message||'account created — waiting for admin approval');return}
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
      document.getElementById('quickbox').style.display='flex';
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
	w.Header().Set("Cache-Control", "no-store")
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
<div class=banner>console</div>
<div class=box><b>mind console</b> — <b>`)
	b.WriteString(htmlEsc(label))
	b.WriteString(`</b> &middot; caps: <span class=dim>`)
	b.WriteString(htmlEsc(strings.Join(claims.Caps, ", ")))
	b.WriteString(`</span><a class=btn style="float:right" href=/v1/web/logout>logout</a></div>`)

	if !consoleUI && !sshUI {
		b.WriteString(`<div class=box>
<b>Доступа пока нет</b>
<p class=dim>Аккаунт создан, но администратор ещё не выдал доступ к консоли.
Попросите администратора выдать доступ, затем войдите заново.</p>
</div>`)
	}
	if consoleUI {
		b.WriteString(`<div class=box>
<b>Что это за страница?</b>
<p class=dim>Это панель управления сервером Mindustry. Обычно нужно только
«Перезапустить» сервер после установки плагина или карты. Остальное — для продвинутых.</p>
</div>
<div class=box>
<b>Сервер</b> <span id=svc class=dim>…</span>
<button onclick=svc('start')>Запустить</button>
<button onclick=svc('restart')>Перезапустить</button>
<button onclick=svc('stop')>Остановить</button>
<div class=stat id=stat style="margin-top:6px">…</div>
<p class=dim style="margin:8px 0 0">«Перезапустить» — применить установленные плагины и карты. «Остановить» выключает сервер.</p>
</div>
<div class=box>
<b>Плагины</b> <span class=dim>(файлы .jar)</span>
<p class=dim style="margin:6px 0">Вставьте ссылку на плагин. Можно ссылку на страницу
GitHub (репозиторий или релиз) — файл .jar найдётся автоматически. Либо прямую ссылку на .jar.</p>
<div style="margin:8px 0">
<input id=purl size=50 placeholder="https://github.com/Kieaer/Essentials">
<button onclick=fetchFile('plugins')>Установить</button>
</div>
<details style="margin:4px 0 8px"><summary class=dim>Как найти ссылку?</summary>
<p class=dim>1. Откройте страницу плагина на GitHub.<br>
2. Скопируйте адрес самой страницы — этого достаточно, файл .jar найдётся сам.<br>
3. Вручную: Releases → нужный релиз → Assets → скопируйте ссылку на файл .jar.</p></details>
<table id=ptab><tr><th>права</th><th>размер</th><th>файл</th><th></th></tr></table>
</div>
<div class=box>
<b>Карты</b> <span class=dim>(файлы .msav)</span>
<p class=dim style="margin:6px 0">Так же: ссылка на страницу GitHub или прямая ссылка на файл .msav.</p>
<div style="margin:8px 0">
<input id=murl size=50 placeholder="https://github.com/user/repo (или прямая ссылка на .msav)">
<button onclick=fetchFile('maps')>Установить</button>
</div>
<details style="margin:4px 0 8px"><summary class=dim>Как найти ссылку?</summary>
<p class=dim>Скопируйте адрес страницы репозитория с картой — файл .msav найдётся автоматически.
Либо используйте прямую ссылку на файл .msav.</p></details>
<table id=mtab><tr><th>права</th><th>размер</th><th>файл</th><th></th></tr></table>
</div>
<div class=box>
<b>Терминал</b> <span class=dim>(для продвинутых)</span> — mind@pc &middot; домашняя папка /home/mind
<button onclick=connect() id=btn>Подключиться</button>
<button onclick=disconnect() disabled id=dis>Отключиться</button>
<div id=term></div>
</div>`)
	}
	if sshUI {
		b.WriteString(`<div class=box>
<b>root SSH</b> <span class=dim>(полный root-доступ к ПК — только для админов)</span>
<button onclick=sshConnect() id=sbtn>Подключиться</button>
<button onclick=sshDisconnect() disabled id=sdis>Отключиться</button>
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
  if(s.error){document.getElementById('stat').textContent='ошибка: '+s.error;return}
  document.getElementById('stat').textContent='нагрузка '+(s.load||'?')+' · '+(s.mem||'')+' · '+(s.disk||'')+' · udp:'+(s.udp==='up'?'вкл':'выкл');
  document.getElementById('svc').textContent=(s.service||'?');
}
async function svc(a){msg('выполняю: '+a+'…');const r=await j('/v1/console/service',{action:a});msg(r.ok?('готово: '+a):('ошибка: '+(r.error||'fail')));setTimeout(refresh,1500)}
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
async function del(kind,name){if(!confirm('Удалить '+name+'?'))return;msg('удаляю '+name+'…');await fetch('/v1/console/file?kind='+kind+'&name='+encodeURIComponent(name),{method:'DELETE'});ls(kind,kind==='plugins'?'ptab':'mtab')}
async function fetchFile(kind){
  const inp=document.getElementById(kind==='plugins'?'purl':'murl');
  if(!inp.value.trim()){msg('вставьте ссылку');return}
  msg('загружаю…');
  const r=await j('/v1/console/fetch',{kind:kind,url:inp.value.trim()});
  msg(r.ok?('Готово: '+r.name+' ('+r.size+' байт). '+r.note):('Ошибка: '+(r.error||'fail')));
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
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	page := `<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"><title>rival — error</title><style>` + bwCSS + `
.center{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:80vh;text-align:center}
.code{font-size:64px;font-weight:bold;margin:0}
.msg-big{font-size:18px;margin-top:12px}
.sub{margin-top:20px}
</style></head><body oncontextmenu="return false">
<div class=center>
<div class=banner>mindustry</div>
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
