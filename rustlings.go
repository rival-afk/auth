package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// hostRouter dispatches requests whose Host matches a configured static host to
// the static file server; everything else goes to the main mux. This lets one
// Go service serve both the API (auth/console) and the Rustlings frontend.
func (s *Server) hostRouter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		if dir, ok := s.cfg.StaticHosts[host]; ok {
			s.serveStaticHost(w, r, dir)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func setStaticHeaders(w http.ResponseWriter, p string) {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".wasm":
		w.Header().Set("Content-Type", "application/wasm")
	case ".bundle", ".data":
		w.Header().Set("Content-Type", "application/octet-stream")
	case ".js", ".mjs":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".json":
		w.Header().Set("Content-Type", "application/json")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	case ".webp":
		w.Header().Set("Content-Type", "image/webp")
	case ".ttf":
		w.Header().Set("Content-Type", "font/ttf")
	case ".html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	switch strings.ToLower(filepath.Ext(p)) {
	// Движок компилятора и шрифты неизменяемы — кэшируем навсегда.
	case ".wasm", ".bundle", ".ttf":
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
}

func (s *Server) serveStaticHost(w http.ResponseWriter, r *http.Request, dir string) {
	if strings.HasPrefix(r.URL.Path, "/api/rustlings/") {
		s.rustlingsAPI(w, r)
		return
	}

	clean := filepath.Clean("/" + r.URL.Path)
	full := filepath.Join(dir, clean)
	// Защита от выхода за пределы каталога.
	if !strings.HasPrefix(full, filepath.Clean(dir)+string(os.PathSeparator)) && full != filepath.Clean(dir) {
		http.NotFound(w, r)
		return
	}

	if fileExists(full) {
		setStaticHeaders(w, full)
		http.ServeFile(w, r, full)
		return
	}
	if idx := filepath.Join(full, "index.html"); fileExists(idx) {
		setStaticHeaders(w, idx)
		http.ServeFile(w, r, idx)
		return
	}
	if p := full + ".html"; fileExists(p) {
		setStaticHeaders(w, p)
		http.ServeFile(w, r, p)
		return
	}
	if p := filepath.Join(dir, "404.html"); fileExists(p) {
		b, _ := os.ReadFile(p)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		w.Write(b)
		return
	}
	http.NotFound(w, r)
}

// rustlingsAPI implements the per-account progress backend for the Rustlings
// frontend. Identity comes from the shared `rival_web` cookie.
func (s *Server) rustlingsAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/rustlings/")
	claims, ok := s.webClaims(r)

	if path == "me" {
		if !ok {
			writeJSON(w, 200, map[string]any{"loggedIn": false})
			return
		}
		writeJSON(w, 200, map[string]any{
			"loggedIn": true,
			"user": map[string]any{
				"id":       claims.KID,
				"username": claims.UN,
				"role":     claims.Role,
			},
		})
		return
	}

	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	uid := claims.KID

	switch {
	case path == "progress" && r.Method == http.MethodGet:
		s.rustlingsProgress(w, uid)
	case path == "progress/visit" && r.Method == http.MethodPost:
		s.rustlingsProgressWrite(w, r, uid, false)
	case path == "progress/complete" && r.Method == http.MethodPost:
		s.rustlingsProgressWrite(w, r, uid, true)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) rustlingsProgress(w http.ResponseWriter, uid string) {
	progress := map[string][]string{}
	rows, err := s.db.Query(`SELECT course_id, slug FROM rustlings_progress WHERE user_id=? AND completed=1 ORDER BY completed_at`, uid)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var c, sl string
			if rows.Scan(&c, &sl) == nil {
				progress[c] = append(progress[c], sl)
			}
		}
	}

	last := map[string]map[string]string{}
	lrows, err := s.db.Query(`SELECT course_id, slug, title FROM rustlings_last_lesson WHERE user_id=?`, uid)
	if err == nil {
		defer lrows.Close()
		for lrows.Next() {
			var c, sl, t string
			if lrows.Scan(&c, &sl, &t) == nil {
				last[c] = map[string]string{"slug": sl, "title": t}
			}
		}
	}

	writeJSON(w, 200, map[string]any{"progress": progress, "lastLesson": last})
}

func (s *Server) rustlingsProgressWrite(w http.ResponseWriter, r *http.Request, uid string, complete bool) {
	var body struct {
		CourseID string `json:"courseId"`
		Slug     string `json:"slug"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil || body.CourseID == "" || body.Slug == "" {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)

	if complete {
		s.db.Exec(`INSERT INTO rustlings_progress (user_id, course_id, slug, completed, visited_at, completed_at)
			VALUES (?,?,?,1,?,?)
			ON CONFLICT(user_id, course_id, slug) DO UPDATE SET completed=1, completed_at=excluded.completed_at`,
			uid, body.CourseID, body.Slug, now, now)
	} else {
		s.db.Exec(`INSERT INTO rustlings_progress (user_id, course_id, slug, completed, visited_at)
			VALUES (?,?,?,0,?)
			ON CONFLICT(user_id, course_id, slug) DO UPDATE SET visited_at=excluded.visited_at`,
			uid, body.CourseID, body.Slug, now)
	}

	s.db.Exec(`INSERT INTO rustlings_last_lesson (user_id, course_id, slug, title, updated_at)
		VALUES (?,?,?,?,?)
		ON CONFLICT(user_id, course_id) DO UPDATE SET slug=excluded.slug, title=excluded.title, updated_at=excluded.updated_at`,
		uid, body.CourseID, body.Slug, body.Slug, now)

	writeJSON(w, 200, map[string]bool{"ok": true})
}
