package main

// mindpage.go — отдельная лендинг mind.rival-afk.com (Mindustry-сервер itz_rival).
// Отдаётся из rootHandler, когда хост = mind.rival-afk.com (и не json-запрос).
// Стиль — Nolejje Ember (bg #0b0b0f, accent #ff3355, Unbounded/JetBrains Mono);
// Unbounded подключается с базового сайта (rival-afk.com/assets/fonts/fonts.css),
// базовые Inter/JBM свои — /console/*.ttf. Статус живой: тот же prober —
// probeMind на 10.66.0.2:6567 (+ ssh-проба пк, чтобы объяснить, кто спит).

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

const mindCSS = `
@font-face{font-family:Inter;font-style:normal;font-weight:400;font-display:swap;src:url(/console/inter-400.ttf) format('truetype')}
@font-face{font-family:'JetBrains Mono';font-style:normal;font-weight:400;font-display:swap;src:url(/console/jbmono-400.ttf) format('truetype')}
*{box-sizing:border-box;margin:0}
:root{--bg:#0b0b0f;--surface:rgba(255,255,255,.04);--border:rgba(255,255,255,.08);--accent:#ff3355;--accent-soft:#ff6a83;--label:#ff8ca0;--text:#ece0df;--muted:#9a9aa1}
body{background:var(--bg);color:var(--text);font:16px/1.7 'JetBrains Mono',ui-monospace,monospace;-webkit-text-size-adjust:100%}
.wrap{max-width:860px;margin:0 auto;padding:36px 18px 60px}
header.top{display:flex;align-items:center;justify-content:space-between;gap:14px}
.brand{font-weight:700;color:var(--text);text-decoration:none;letter-spacing:.02em}
.brand em{color:var(--accent);font-style:normal}
.top-links{display:flex;gap:6px;flex-wrap:wrap}
.top-links a{font-size:12.5px;color:#ccc;text-decoration:none;padding:9px 13px;border:1px solid var(--border);border-radius:999px;background:var(--surface);transition:.2s}
.top-links a:hover{border-color:rgba(255,51,85,.5);color:#fff}
.hero{margin-top:64px}
.tag{display:inline-block;font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--label)}
h1{margin-top:16px;font-family:Unbounded,Inter,system-ui,sans-serif;font-weight:900;font-size:clamp(42px,10vw,96px);line-height:.95;letter-spacing:-.02em;color:#fff}
h1 .red{color:var(--accent)}
.sub{margin-top:16px;max-width:640px;color:var(--muted);font-size:15.5px;line-height:1.9}
.stat{margin-top:28px;display:inline-flex;align-items:center;gap:12px;padding:14px 20px;border:1px solid var(--border);border-radius:999px;background:var(--surface)}
.dot{width:10px;height:10px;border-radius:50%;background:#91e7b5;box-shadow:0 0 12px rgba(145,231,181,.8);animation:pulse 1.6s infinite}
.dot.asleep{background:#8f9099;box-shadow:none;animation:none}
@keyframes pulse{50%{opacity:.4}}
.stat b{font-family:Unbounded,Inter,sans-serif;font-size:15px;letter-spacing:.08em}
.stat span{color:var(--muted);font-size:13px}
.card{margin-top:26px;padding:26px 28px;border:1px solid var(--border);border-radius:30px;background:linear-gradient(180deg,rgba(255,255,255,.04),rgba(255,255,255,.02))}
.card h2{margin-bottom:16px;font-family:Unbounded,Inter,sans-serif;font-weight:700;font-size:21px;color:#fff}
.connect{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.code{padding:12px 18px;border:1px solid var(--border);border-radius:16px;background:rgba(0,0,0,.45);font-size:15px;color:#fff}
.code span{color:var(--accent)}
.steps{margin-top:14px;color:var(--muted);font-size:14.5px;line-height:2}
.steps b{color:var(--text)}
.note{margin-top:12px;color:var(--muted);font-size:13.5px;border-top:1px solid var(--border);padding-top:14px}
.facts{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:24px}
.fact{padding:18px;border:1px solid var(--border);border-radius:20px;background:var(--surface);text-align:center}
.fact .v{display:block;margin-top:8px;font-family:Unbounded,Inter,sans-serif;font-size:19px;color:#fff}
.foot{margin-top:40px;text-align:center;color:var(--muted);font-size:12px}
.foot a{color:var(--accent-soft)}
@media (max-width:720px){.facts{grid-template-columns:1fr}.hero{margin-top:40px}.card{padding:20px;border-radius:22px}}
@media (prefers-reduced-motion:reduce){.dot{animation:none}}
`

// mindPageHandler — лендинг Mindustry-сервера: подключение + живой статус.
func (s *Server) mindPageHandler(w http.ResponseWriter, r *http.Request) {
	var mind, pc statService
	found := 0
	for _, svc := range s.gatherStats().Services {
		if svc.Name == "mind.rival-afk.com" {
			mind = svc
			found++
		}
		if svc.Name == "pc(ssh)" {
			pc = svc
			found++
		}
		if found == 2 {
			break
		}
	}

	// статус: игра отвечает?
	var stateBadge, stateText string
	var dotCls string
	switch {
	case mind.Up:
		stateBadge = `<b style="color:#91e7b5">LIVE</b>`
		stateText = fmt.Sprintf("сервер отвечает · ping %.0f ms", mind.Latency)
		dotCls = ""
	case pc.Up:
		stateBadge = `<b style="color:#ffb04d">WITHOUT GAME PORT</b>`
		stateText = "пк на связи, но 6567 не слушает — скоро подниму"
		dotCls = "asleep"
	default:
		stateBadge = `<b style="color:#9a9aa1">SLEEPING</b>`
		stateText = "пк выключен — владелец разбудит по wake-on-LAN"
		dotCls = "asleep"
	}

	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="ru"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>Mindustry — itz_rival · mind.rival-afk.com</title>` +
		`<meta name="description" content="Mindustry-сервер itz_rival: подключение mind.rival-afk.com, порт 6567. Живой статус. всё на своих узлах: телефон держит туннель, играется на пк.">` +
		`<link rel="canonical" href="https://mind.rival-afk.com/">` +
		`<meta name="robots" content="index,follow">` +
		`<meta property="og:title" content="Mindustry — itz_rival">` +
		`<meta property="og:description" content="Свой Mindustry-сервер: mind.rival-afk.com:6567. Живой статус и как подключиться.">` +
		`<meta property="og:url" content="https://mind.rival-afk.com/">` +
		`<meta property="og:type" content="website">` +
		`<link rel="icon" type="image/svg+xml" href="/favicon.svg">` +
		`<link rel="stylesheet" href="https://rival-afk.com/assets/fonts/fonts.css">` +
		`<style>` + mindCSS + `</style></head><body><div class="wrap">`)

	// шапка
	b.WriteString(`<header class="top"><a class="brand" href="/">mind<em>ustry</em></a><nav class="top-links">` +
		`<a href="https://rival-afk.com/">разработчик</a>` +
		`<a href="https://nolejje.rival-afk.com/">nolejje</a>` +
		`<a href="https://file.rival-afk.com/">fileshare</a></nav></header>`)

	// hero
	b.WriteString(`<div class="hero"><span class="tag">SELF-HOSTED GAME SERVER</span>` +
		`<h1>MIND<span class="red">USTRY</span></h1>` +
		`<p class="sub">Личный Mindustry-сервер itz_rival. Играется на домашнем пк, живёт благодаря wake-on-LAN через телефон и реверс-туннелю. Публичный адрес — вот этот домен, делиться можно свободно.</p>` +
		`<div class="stat"><span class="dot ` + dotCls + `"></span>` + stateBadge +
		`<span>` + stateText + `</span></div>` +
		`<div class="facts">` +
		`<div class="fact"><span class="tag">адрес</span><span class="v">mind.rival-afk.com</span></div>` +
		`<div class="fact"><span class="tag">порт</span><span class="v">6567</span></div>` +
		`<div class="fact"><span class="tag">протокол</span><span class="v">UDP</span></div>` +
		`</div></div>`)

	// карточка подключения
	b.WriteString(`<section class="card"><h2>как подключиться</h2>` +
		`<div class="connect"><span class="code">host&nbsp;<span>mind.rival-afk.com</span></span>` +
		`<span class="code">port&nbsp;6567</span></div>` +
		`<p class="steps">1. открой Mindustry → <b>Join game</b><br>` +
		`2. выбери <b>Direct connect</b><br>` +
		`3. вбей адрес выше (порт уже стоит по умолчанию)<br>` +
		`4. если статус <b>SLEEPING</b> — сервер пока спит, заходи позже</p>` +
		`<p class="note">сервер поднимается не всегда: домашний пк живёт по расписанию владельца. Когда игрока-хостера нет рядом — баюшки. Внутри игры имена, моды и карта произвольные: от ванильных до модов с переплавкой.</p>` +
		`</section>` +
		`</div>` +
		`<p class="foot">refreshed ` + time.Now().Format(time.RFC3339) +
		` · status есть и в <a href="/?format=json">json</a> · сделано без фреймворков, ресурс: <a href="https://rival-afk.com/">rival-afk.com</a></p>` +
		`</body></html>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Refresh", "30")
	_, _ = w.Write([]byte(b.String()))
}
