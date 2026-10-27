package main

// devapi.go — API личной страницы itz_rival (rival-afk.com).
//
// ИСТОЧНИК ПУБЛИЧНЫХ ДАННЫХ — ОДИН JSON: /var/www/rival/data.json.
// Из него рендерится и сам сайт (app.js fetch /data.json), и этот API:
//
//	GET /api/dev        — data.json + age (возраст из root-only конфига)
//	GET /api/dev/age    — только возраст (скользящий, считается по TZ)
//	GET /api/dev/stack  — только блок "stack"
//
// Приватные данные (дата рождения, часовой пояс) лежат отдельно в
// /var/lib/rival/dev-profile.json (chmod 600) и в JSON-профиль
// в полном виде не попадают — наружу уходит только Lê age.years.
// Владелец правит data.json у себя (github canonical → tar-деплой сайта),
// возрастной конфиг — прямо на VPS, пересборка не нужна.

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	devProfileCfgPath = "/var/lib/rival/dev-profile.json" // приватный (600)
	devDataPath       = "/var/www/rival/data.json"        // единый публичный JSON
)

// devCfg — приватный файловый конфиг (правится владельцем на VPS вручную).
type devCfg struct {
	Birthday string `json:"birthday"` // YYYY-MM-DD
	TZ       string `json:"tz"`       // IANA, напр. Europe/Minsk
}

// devAge считывает возраст из профиль-конфига и возвращает готовую карту для JSON.
// Наружу уходит только возраст; никакие даты (ДР, следующее ДР) не отдаём —
// они приватные и лежат root-only ('/var/lib/rival/dev-profile.json', chmod 600).
func devAge(cfg devCfg) (map[string]interface{}, bool) {
	bday, err := time.Parse("2006-01-02", strings.TrimSpace(cfg.Birthday))
	if err != nil {
		return nil, false
	}
	loc := time.UTC
	if tz, err := time.LoadLocation(strings.TrimSpace(cfg.TZ)); err == nil && strings.TrimSpace(cfg.TZ) != "" {
		loc = tz
	}
	now := time.Now().In(loc)
	b := bday.In(loc)

	// точные годы: прошло ли ДР в этом году
	thisYear := time.Date(now.Year(), b.Month(), b.Day(), 0, 0, 0, 0, loc)
	years := now.Year() - b.Year()
	if now.Before(thisYear) {
		years--
	}
	// наружу — только возраст: даты (ДР, след. ДР, дни жизни) не публикуем
	return map[string]interface{}{
		"years": years,
	}, true
}

// devDataCache — кэш data.json по mtime: файл перечитывается при правке.
var devDataCache struct {
	mu    sync.Mutex
	mtime int64
	data  map[string]interface{}
}

// devData читает единый JSON (с mtime-кэшем).
func devData() (map[string]interface{}, error) {
	devDataCache.mu.Lock()
	defer devDataCache.mu.Unlock()
	fi, err := os.Stat(devDataPath)
	if err != nil {
		return nil, err
	}
	if devDataCache.data != nil && fi.ModTime().Unix() == devDataCache.mtime {
		return devDataCache.data, nil
	}
	b, err := os.ReadFile(devDataPath)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, err
	}
	devDataCache.mtime = fi.ModTime().Unix()
	devDataCache.data = data
	return data, nil
}

// devAgeCurrent — возраст из приватного конфига либо name===nil-заглушка.
func devAgeCurrent() map[string]interface{} {
	var cfg devCfg
	if b, err := os.ReadFile(devProfileCfgPath); err == nil {
		if json.Unmarshal(b, &cfg) == nil {
			if age, ok := devAge(cfg); ok {
				return age
			}
		}
	}
	return map[string]interface{}{
		"years": nil,
		"note":  "age unavailable: profile config missing on server",
	}
}

// devProfileAPI отдаёт весь data.json + age + generated_at.
func (s *Server) devProfileAPI(w http.ResponseWriter, r *http.Request) {
	data, err := devData()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "dev data missing: "+err.Error())
		return
	}
	out := make(map[string]interface{}, len(data)+2)
	for k, v := range data {
		out[k] = v
	}
	delete(out, "_комментарий") // служебный ключ не публикуем
	out["age"] = devAgeCurrent()
	out["generated_at"] = time.Now().UTC().Format(time.RFC3339)
	writeJSON(w, http.StatusOK, out)
}

// devSubAPI точечные роуты под каждым разделом.
func (s *Server) devSubAPI(w http.ResponseWriter, r *http.Request, sub string) {
	switch sub {
	case "age":
		writeJSON(w, http.StatusOK, devAgeCurrent())
	case "stack":
		data, err := devData()
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, "dev data missing: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"stack": data["stack"]})
	default:
		s.devProfileAPI(w, r)
	}
}

// devAPIRouter вызывается из hostRouter: обрабатывает /api/dev/* для apex-домена.
func (s *Server) devAPIRouter(w http.ResponseWriter, r *http.Request) {
	sub := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/dev"), "/")
	if sub == "" {
		s.devProfileAPI(w, r)
		return
	}
	// /api/dev/<один сегмент> — подроут, остальное — полный профиль
	if strings.Contains(sub, "/") {
		http.NotFound(w, r)
		return
	}
	s.devSubAPI(w, r, sub)
}
