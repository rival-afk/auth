package main

// devapi.go — API личной страницы itz_rival (rival-afk.com).
//
// Приватные данные (дата рождения, часовой пояс) лежат в отдельном
// root-only конфиге /var/lib/rival/dev-profile.json (chmod 600),
// чтобы они не попадали в публичные статические файлы сайта.
// Владелец правит этот файл прямо на VPS — пересборка не нужна.
//
// Публичные данные (ник, стек, проекты, ссылки) лежат ниже в Go-литерале:
// их правят коммитом в main, деплой такой же, как у самого auth-сервера.
//
// Роуты (только для хостов rival-afk.com и www.rival-afk.com):
//   GET /api/dev        — полный профиль
//   GET /api/dev/age    — только возраст (скользящий, считается по TZ)
//   GET /api/dev/stack  — только стек

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
)

const devProfileCfgPath = "/var/lib/rival/dev-profile.json"

// devProject — карточка проекта в API.
type devProject struct {
	Name   string   `json:"name"`
	Link   string   `json:"link,omitempty"`
	Desc   string   `json:"desc"`
	Stack  []string `json:"stack"`
	Status string   `json:"status,omitempty"`
}

// devLinks — соцсети/контакты.
type devLinks struct {
	Telegram string `json:"telegram"`
	GitHub   string `json:"github"`
	Website  string `json:"website,omitempty"`
}

// devStatic — публичная часть профиля (правится коммитом).
type devStatic struct {
	Nickname    string              `json:"nickname"`
	Twitter     string              `json:"twitter,omitempty"` // резерв
	Role        string              `json:"role"`
	Location    string              `json:"location"`
	Stack       []string            `json:"stack"`
	StackGroups map[string][]string `json:"stack_groups"`
	Projects    []devProject        `json:"projects"`
	Links       devLinks            `json:"links"`
}

// devCfg — файловый конфиг (правится владельцем на VPS вручную).
type devCfg struct {
	Birthday string `json:"birthday"` // YYYY-MM-DD
	TZ       string `json:"tz"`       // IANA, напр. Europe/Minsk
}

// devPublic — то, что отдаёт API.
type devPublic struct {
	Nickname    string                 `json:"nickname"`
	Role        string                 `json:"role"`
	Location    string                 `json:"location"`
	Age         map[string]interface{} `json:"age"`
	Stack       []string               `json:"stack"`
	StackGroups map[string][]string    `json:"stack_groups"`
	Projects    []devProject           `json:"projects"`
	Links       devLinks               `json:"links"`
	Infra       []map[string]string    `json:"infra"`
	Generated   string                 `json:"generated_at"`
}

// devStaticProfile — публичные данные itz_rival.
var devStaticProfile = devStatic{
	Nickname: "itz_rival",
	Role:     "systems developer / self-hosting",
	Location: "Belarus",
	Stack:    []string{"rust", "go", "python", "javascript", "sql", "nginx", "html", "css", "docker"},
	StackGroups: map[string][]string{
		"languages": {"rust", "go", "python", "javascript", "sql"},
		"web":       {"html", "css", "nginx"},
		"infra":     {"docker", "linux", "sqlite"},
	},
	Projects: []devProject{
		{
			Name:   "rsh",
			Link:   "https://github.com/rival-afk/rsh",
			Desc:   "ssh-шлюз с авторизацией через собственный auth-сервер: provision ключей на лету, reverse-proxies, WoL, exec по хостам. Один бинарник, ноль зависимостей.",
			Stack:  []string{"go", "ed25519"},
			Status: "в бою",
		},
		{
			Name:   "rival-auth",
			Link:   "https://github.com/rival-afk/auth",
			Desc:   "auth-сервер и API-гейт всего зеноку: выдача ключей rsh, net-дискавери, ACME, веб-консоль с xterm. Этот домен живёт внутри него.",
			Stack:  []string{"go", "sqlite", "acme"},
			Status: "в бою",
		},
		{
			Name:   "nolejje",
			Link:   "https://nolejje.rival-afk.com",
			Desc:   "магазин запчастей на Go, который хостится на телефоне и из-за реверс-туннеля переживает всё.",
			Stack:  []string{"go", "sql", "html", "css"},
			Status: "в бою",
		},
		{
			Name:   "rustlings",
			Link:   "https://rustlings.rival-afk.com",
			Desc:   "интерактивный курс Rust с прогресс-трекингом прямо в браузере.",
			Stack:  []string{"rust", "javascript", "css"},
			Status: "жив",
		},
		{
			Name:  "zenoku",
			Link:  "",
			Desc:  "личная mesh-инфраструктура: VPS + телефон + ПК, runit-сервисы, Telegram-бот и вотчдоги, который сам ловит мой даунтайм.",
			Stack: []string{"go", "bash", "runit"},
		},
	},
	Links: devLinks{
		Telegram: "https://t.me/itz_rival",
		GitHub:   "https://github.com/rival-afk",
		Website:  "https://rival-afk.com",
	},
}

// devInfra — честная карта инфры, которую держит itz_rival.
var devInfra = []map[string]string{
	{"node": "vps", "what": "Debian 13 · rival-auth · nginx · WoL-хост", "uptime": "считал часы без сна"},
	{"node": "phone", "what": "Termux как ядро инфры · runit · реверс-туннель", "uptime": "не спит, служит"},
	{"node": "pc", "what": "Alpine · wake-on-LAN · десктоп-нода", "uptime": "просыпается по rsh pc on"},
}

// devAge считывает возраст из профиль-конфига и возвращает готовую карту для JSON.
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
	nextBirthday := thisYear
	if now.After(thisYear) || now.Equal(thisYear) {
		nextBirthday = thisYear.AddDate(1, 0, 0)
	}
	daysAlive := int(now.Sub(b).Hours() / 24)
	daysToBirthday := int(nextBirthday.Sub(now).Hours()/24) + 1
	return map[string]interface{}{
		"years":            years,
		"days_alive":       daysAlive,
		"next_birthday":    nextBirthday.Format("2006-01-02"),
		"days_to_birthday": daysToBirthday,
	}, true
}

// devProfileAPI отдаёт JSON-профиль: читает /var/lib/rival/dev-profile.json.
func (s *Server) devProfileAPI(w http.ResponseWriter, r *http.Request) {
	var cfg devCfg
	ageOK := false
	var age map[string]interface{}
	if b, err := os.ReadFile(devProfileCfgPath); err == nil {
		if json.Unmarshal(b, &cfg) == nil {
			age, ageOK = devAge(cfg)
		}
	}
	if !ageOK {
		// конфиг не прочитался: не ломаем весь API — отдаём профиль без age
		age = map[string]interface{}{"years": nil, "note": "age unavailable: profile config missing on server"}
	}

	p := devPublic{
		Nickname:    devStaticProfile.Nickname,
		Role:        devStaticProfile.Role,
		Location:    devStaticProfile.Location,
		Age:         age,
		Stack:       devStaticProfile.Stack,
		StackGroups: devStaticProfile.StackGroups,
		Projects:    devStaticProfile.Projects,
		Links:       devStaticProfile.Links,
		Infra:       devInfra,
		Generated:   time.Now().UTC().Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, p)
}

// devSubAPI точечные роуты под каждым разделом.
func (s *Server) devSubAPI(w http.ResponseWriter, r *http.Request, sub string) {
	switch sub {
	case "age":
		var cfg devCfg
		if b, err := os.ReadFile(devProfileCfgPath); err == nil {
			if json.Unmarshal(b, &cfg) == nil {
				if age, ok := devAge(cfg); ok {
					writeJSON(w, http.StatusOK, age)
					return
				}
			}
		}
		writeErr(w, http.StatusServiceUnavailable, "profile config missing")
	case "stack":
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"stack":  devStaticProfile.Stack,
			"groups": devStaticProfile.StackGroups,
		})
	default:
		s.devProfileAPI(w, r)
	}
}

// devAPIRouter вызывается из hostRouter: обрабатывает /api/dev/* для apex-домена.
func (s *Server) devAPIRouter(w http.ResponseWriter, r *http.Request) {
	sub := strings.TrimPrefix(r.URL.Path, "/api/dev/")
	sub = strings.TrimSuffix(sub, "/")
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
