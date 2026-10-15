package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

// ---- users (password accounts) ----
//
// users.id is referenced from web session claims as "u:"+id (Claims.KID).
// keys.user_id links browser-bound / .rsh keys to a user; empty = standalone key.

type bindChallenge struct {
	userID string
	ts     time.Time
}

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{2,31}$`)

func (s *Server) allHostsJSON() string {
	hosts := []string{}
	for h := range s.cfg.Hosts {
		hosts = append(hosts, h)
	}
	hj, _ := json.Marshal(hosts)
	return string(hj)
}

func (s *Server) userClaims(id, username, role, capsJSON string) *Claims {
	var caps []string
	json.Unmarshal([]byte(capsJSON), &caps)
	hosts := []string{}
	for h := range s.cfg.Hosts {
		hosts = append(hosts, h)
	}
	return &Claims{KID: "u:" + id, UN: username, Role: role, Hosts: hosts, Caps: caps}
}

func (s *Server) lookupUserByUsername(username string) (id, hash, role, capsJSON string, ok bool) {
	err := s.db.QueryRow(`SELECT id, pass_hash, role, caps FROM users WHERE username = ?`, strings.ToLower(username)).
		Scan(&id, &hash, &role, &capsJSON)
	return id, hash, role, capsJSON, err == nil
}

// POST /v1/web/register — open to everyone; always creates a regular user with console cap.
func (s *Server) webRegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad request")
		return
	}
	username := strings.ToLower(strings.TrimSpace(req.Username))
	if !usernameRe.MatchString(username) {
		writeErr(w, 400, "username: 3-32 chars, a-z 0-9 _ . -")
		return
	}
	if len(req.Password) < 8 {
		writeErr(w, 400, "password: min 8 characters")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "hash error")
		return
	}
	id := randID()
	// every self-registered account is a regular user with console access only
	if _, err := s.db.Exec(`INSERT INTO users (id, username, pass_hash, role, caps, created_at) VALUES (?,?,?,?,?,?)`,
		id, username, string(hash), "user", `["console"]`, time.Now().Unix()); err != nil {
		writeErr(w, 409, "username taken")
		return
	}
	s.issueWebCookie(w, s.userClaims(id, username, "user", `["console"]`))
	writeJSON(w, 200, map[string]interface{}{"ok": true, "username": username, "role": "user", "caps": []string{"console"}})
}

// POST /v1/web/passlogin — username+password.
func (s *Server) webPassLoginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad request")
		return
	}
	id, hash, role, capsJSON, ok := s.lookupUserByUsername(req.Username)
	if !ok || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		writeErr(w, 401, "bad username or password")
		return
	}
	var caps []string
	json.Unmarshal([]byte(capsJSON), &caps)
	if !containsStr(caps, "console") && !containsStr(caps, "ssh") {
		writeErr(w, 403, "no console access for this account")
		return
	}
	username := strings.ToLower(strings.TrimSpace(req.Username))
	s.issueWebCookie(w, s.userClaims(id, username, role, capsJSON))
	writeJSON(w, 200, map[string]interface{}{"ok": true, "username": username, "role": role, "caps": caps})
}

// POST /v1/web/bindnonce — issue a binding challenge for the logged-in user.
func (s *Server) webBindNonceHandler(w http.ResponseWriter, r *http.Request) {
	c, ok := s.webClaims(r)
	if !ok {
		writeErr(w, 401, "not logged in")
		return
	}
	if !strings.HasPrefix(c.KID, "u:") {
		writeErr(w, 403, "password account required")
		return
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	hexNonce := hex.EncodeToString(nonce)
	s.bindMu.Lock()
	now := time.Now()
	for k, v := range s.bindMap {
		if now.Sub(v.ts) > 5*time.Minute {
			delete(s.bindMap, k)
		}
	}
	s.bindMap[hexNonce] = bindChallenge{userID: strings.TrimPrefix(c.KID, "u:"), ts: now}
	s.bindMu.Unlock()
	writeJSON(w, 200, map[string]string{"nonce": hexNonce})
}

// POST /v1/web/bindkey — verify signature over bind nonce, bind pubkey to user.
func (s *Server) webBindKeyHandler(w http.ResponseWriter, r *http.Request) {
	c, ok := s.webClaims(r)
	if !ok {
		writeErr(w, 401, "not logged in")
		return
	}
	if !strings.HasPrefix(c.KID, "u:") {
		writeErr(w, 403, "password account required")
		return
	}
	var req struct {
		Pubkey string `json:"pubkey"`
		Nonce  string `json:"nonce"`
		Sig    string `json:"sig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Pubkey) == "" {
		writeErr(w, 400, "pubkey and nonce required")
		return
	}
	s.bindMu.Lock()
	bc, okB := s.bindMap[req.Nonce]
	delete(s.bindMap, req.Nonce)
	s.bindMu.Unlock()
	uid := strings.TrimPrefix(c.KID, "u:")
	if !okB || bc.userID != uid || time.Since(bc.ts) > 5*time.Minute {
		writeErr(w, 401, "bad or expired bind challenge")
		return
	}
	pub := normalizePub(req.Pubkey)
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
	var existingUser string
	err = s.db.QueryRow(`SELECT user_id FROM keys WHERE pubkey = ?`, pub).Scan(&existingUser)
	if err == nil {
		if existingUser == uid {
			writeJSON(w, 200, map[string]interface{}{"ok": true, "already": true})
			return
		}
		writeErr(w, 409, "key already bound to another account")
		return
	}
	label := "browser:" + c.UN
	cj, _ := json.Marshal(c.Caps)
	id := randID()
	if _, err := s.db.Exec(`INSERT INTO keys (id, pubkey, role, hosts, label, caps, user_id, created_at) VALUES (?,?,?,?,?,?,?,?)`,
		id, pub, c.Role, s.allHostsJSON(), label, string(cj), uid, time.Now().Unix()); err != nil {
		writeErr(w, 409, "key already exists or db error")
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "id": id})
}

// canGrantCaps: admin can only grant caps they themselves have.
func canGrantCaps(granter *Claims, caps []string) bool {
	for _, c := range caps {
		if !containsStr(granter.Caps, c) {
			return false
		}
	}
	return true
}

func validCaps(caps []string) bool {
	for _, c := range caps {
		if c != "console" && c != "ssh" {
			return false
		}
	}
	return true
}

// GET/POST /v1/admin/users — bearer-auth admin management of password accounts.
func (s *Server) adminUsersHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if claims.Role != "admin" {
		writeErr(w, 403, "admin only")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.Query(`SELECT id, username, role, caps, created_at FROM users ORDER BY created_at`)
		if err != nil {
			writeErr(w, 500, "db error")
			return
		}
		defer rows.Close()
		out := []map[string]interface{}{}
		for rows.Next() {
			var id, username, role, capsJSON string
			var ca int64
			rows.Scan(&id, &username, &role, &capsJSON, &ca)
			var caps []string
			json.Unmarshal([]byte(capsJSON), &caps)
			out = append(out, map[string]interface{}{
				"id": id, "username": username, "role": role, "caps": caps, "created_at": ca,
			})
		}
		writeJSON(w, 200, out)
	case http.MethodPost:
		var req struct {
			Username string   `json:"username"`
			Password string   `json:"password"`
			Role     string   `json:"role"`
			Caps     []string `json:"caps"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, 400, "bad request")
			return
		}
		username := strings.ToLower(strings.TrimSpace(req.Username))
		if !usernameRe.MatchString(username) {
			writeErr(w, 400, "username: 3-32 chars, a-z 0-9 _ . -")
			return
		}
		if len(req.Password) < 8 {
			writeErr(w, 400, "password: min 8 characters")
			return
		}
		if req.Role != "user" && req.Role != "admin" {
			req.Role = "user"
		}
		if len(req.Caps) == 0 {
			req.Caps = []string{"console"}
		}
		if !validCaps(req.Caps) {
			writeErr(w, 400, "caps must be console and/or ssh")
			return
		}
		// hierarchy: cannot grant caps you don't have yourself
		if !canGrantCaps(claims, req.Caps) {
			writeErr(w, 403, "cannot grant caps you don't have")
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			writeErr(w, 500, "hash error")
			return
		}
		cj, _ := json.Marshal(req.Caps)
		id := randID()
		if _, err := s.db.Exec(`INSERT INTO users (id, username, pass_hash, role, caps, created_at) VALUES (?,?,?,?,?,?)`,
			id, username, string(hash), req.Role, string(cj), time.Now().Unix()); err != nil {
			writeErr(w, 409, "username taken")
			return
		}
		writeJSON(w, 200, map[string]interface{}{"id": id, "username": username, "role": req.Role, "caps": req.Caps})
	default:
		writeErr(w, 405, "method not allowed")
	}
}

// PATCH /v1/admin/users/{id} — change role and/or caps of an existing user.
func (s *Server) adminUserUpdateHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if claims.Role != "admin" {
		writeErr(w, 403, "admin only")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, 400, "missing id")
		return
	}
	var req struct {
		Role string   `json:"role"`
		Caps []string `json:"caps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad request")
		return
	}
	var curRole, curCapsJSON string
	if err := s.db.QueryRow(`SELECT role, caps FROM users WHERE id = ?`, id).Scan(&curRole, &curCapsJSON); err != nil {
		writeErr(w, 404, "not found")
		return
	}
	newRole := req.Role
	if newRole == "" {
		newRole = curRole
	}
	if newRole != "user" && newRole != "admin" {
		writeErr(w, 400, "role must be user or admin")
		return
	}
	newCaps := req.Caps
	if newCaps == nil {
		json.Unmarshal([]byte(curCapsJSON), &newCaps)
	}
	if !validCaps(newCaps) {
		writeErr(w, 400, "caps must be console and/or ssh")
		return
	}
	// hierarchy: admin can only grant what they have (equal or lower)
	if !canGrantCaps(claims, newCaps) {
		writeErr(w, 403, "cannot grant caps you don't have")
		return
	}
	// protect last admin from demotion
	if curRole == "admin" && newRole != "admin" {
		var admins int
		s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&admins)
		if admins <= 1 {
			writeErr(w, 400, "cannot demote the last admin")
			return
		}
	}
	cj, _ := json.Marshal(newCaps)
	if _, err := s.db.Exec(`UPDATE users SET role = ?, caps = ? WHERE id = ?`, newRole, string(cj), id); err != nil {
		writeErr(w, 500, "db error")
		return
	}
	// keep bound browser keys in sync with user's caps/role
	s.db.Exec(`UPDATE keys SET caps = ?, role = ? WHERE user_id = ?`, string(cj), newRole, id)
	writeJSON(w, 200, map[string]interface{}{"ok": true, "id": id, "role": newRole, "caps": newCaps})
}

// DELETE /v1/admin/users/{id}
func (s *Server) adminUserDeleteHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if claims.Role != "admin" {
		writeErr(w, 403, "admin only")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, 400, "missing id")
		return
	}
	// never delete the last admin
	var admins int
	s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&admins)
	var role string
	if err := s.db.QueryRow(`SELECT role FROM users WHERE id = ?`, id).Scan(&role); err != nil {
		writeErr(w, 404, "not found")
		return
	}
	if role == "admin" && admins <= 1 {
		writeErr(w, 400, "cannot delete the last admin")
		return
	}
	res, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		writeErr(w, 500, "db error")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, 404, "not found")
		return
	}
	s.db.Exec(`DELETE FROM keys WHERE user_id = ?`, id)
	writeJSON(w, 200, map[string]interface{}{"deleted": id})
}
