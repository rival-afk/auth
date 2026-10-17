package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type statService struct {
	Name    string  `json:"name"`
	Addr    string  `json:"addr"`
	Up      bool    `json:"up"`
	Latency float64 `json:"latency_ms"`
	Detail  string  `json:"detail,omitempty"`
	Error   string  `json:"error,omitempty"`
}

type statsResp struct {
	Time     int64                    `json:"time"`
	Domain   string                   `json:"domain"`
	What     string                   `json:"what"`
	Server   map[string]string        `json:"server"`
	Load     map[string]interface{}   `json:"load"`
	Services []statService            `json:"services"`
	NetPeers []map[string]interface{} `json:"net_peers"`
	Keys     int                      `json:"issued_keys"`
}

// hostWithoutPort strips :port from a Host header value.
func hostWithoutPort(h string) string {
	if i := strings.LastIndex(h, ":"); i != -1 && !strings.Contains(h[i:], "]") {
		return h[:i]
	}
	return h
}

// hostWhat returns a human-readable description of which API the host is.
func hostWhat(h string) string {
	switch host := hostWithoutPort(strings.ToLower(strings.TrimSpace(h))); host {
	case "rival-afk.com":
		return "apex — main rival-afk domain"
	case "www.rival-afk.com":
		return "web alias of the apex rival-afk.com"
	case "auth.rival-afk.com":
		return "auth API — rsh gateway (keys / tokens / net discovery)"
	case "mc.rival-afk.com":
		return "Minecraft entry — WireGuard DNAT to the PC :25565; this page shows its status"
	case "mind.rival-afk.com":
		return "Mindustry entry — WireGuard DNAT to the PC :6567; this page shows its status"
	case "ssh.rival-afk.com":
		return "SSH retransmit gateway (jump into VPS -> phone -> PC)"
	default:
		return "rival-afk edge — " + host
	}
}

func utsRelease(b []int8) string {
	s := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		s = append(s, byte(c))
	}
	return string(s)
}

func readProc(cond func(string) bool, parse func(string)) {
	// lightweight /proc reader: iterate lines, call parse for lines passing cond
}

func firstField(f func(line string) bool) string { return "" }

func gatherSys() (map[string]string, map[string]interface{}) {
	server := map[string]string{}
	server["hostname"], _ = os.Hostname()
	server["os"] = "linux"
	server["arch"] = runtime.GOARCH
	server["go"] = runtime.Version()
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "PRETTY_NAME=") {
				server["os"] = strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), "\"")
			}
		}
	}
	// kernel via uname is in syscall; keep portable: read /proc osrelease instead
	server["kernel"] = readKernel()
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			server["uptime_s"] = f[0]
		}
	}
	load := map[string]interface{}{}
	load["cpu_count"] = runtime.NumCPU()
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 3 {
			load["load1"], load["load5"], load["load15"] = f[0], f[1], f[2]
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, avail int64
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "MemTotal:") {
				fmt.Sscanf(strings.TrimSpace(l), "MemTotal: %d kB", &total)
			} else if strings.HasPrefix(l, "MemAvailable:") {
				fmt.Sscanf(strings.TrimSpace(l), "MemAvailable: %d kB", &avail)
			}
		}
		load["mem_total_mb"] = total / 1024
		load["mem_used_mb"] = (total - avail) / 1024
	}
	load["disk"] = diskStat("/")
	return server, load
}

func readKernel() string {
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

func diskStat(path string) string {
	// portable-ish via df-free approach not available in pure go without syscall; use /proc/mounts? fallback string
	total, free, err := fsBytes(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%.1fGiB/%.1fGiB free", float64(free)/1e9, float64(total)/1e9)
}

func tcpDialMs(addr string, timeout time.Duration) (time.Duration, net.Conn, error) {
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, timeout)
	return time.Since(start), c, err
}

// ms converts a duration to milliseconds with sub-ms precision so that
// loopback probes do not all collapse to 0.
func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

func probeSSH(name, addr string, timeout time.Duration) statService {
	var d time.Duration
	var c net.Conn
	var err error
	start := time.Now()
	for attempt := 0; attempt < 3; attempt++ {
		d, c, err = tcpDialMs(addr, timeout)
		if err == nil {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if err != nil {
		return statService{Name: name, Addr: addr, Up: false, Latency: ms(time.Since(start)), Error: err.Error()}
	}
	defer c.Close()
	rtt := ms(d)
	detail := "tcp ok"
	c.SetReadDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(c)
	if line, rerr := br.ReadString('\n'); rerr == nil {
		if l := strings.TrimSpace(line); strings.HasPrefix(l, "SSH-") {
			detail = l
			rtt = ms(time.Since(start))
		}
	}
	return statService{Name: name, Addr: addr, Up: true, Latency: rtt, Detail: detail}
}

func probeMC(name, addr string, timeout time.Duration) statService {
	d, c, err := tcpDialMs(addr, timeout)
	start := time.Now().Add(-d)
	if err != nil {
		return statService{Name: name, Addr: addr, Up: false, Error: err.Error()}
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout + 1500*time.Millisecond))
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	var hs bytes.Buffer
	putVarInt(&hs, 0x00)
	putVarInt(&hs, 47)
	putString(&hs, host)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	hs.Write(pb[:])
	putVarInt(&hs, 1)
	if err := writePacket(c, hs.Bytes()); err != nil {
		return statService{Name: name, Addr: addr, Up: false, Error: "handshake: " + err.Error()}
	}
	if err := writePacket(c, []byte{0x00}); err != nil {
		return statService{Name: name, Addr: addr, Up: false, Error: "status: " + err.Error()}
	}
	br := bufio.NewReader(c)
	if _, err := readVarInt(br); err != nil {
		return statService{Name: name, Addr: addr, Up: false, Error: "read len: " + err.Error()}
	}
	pid, err := readVarInt(br)
	if err != nil {
		return statService{Name: name, Addr: addr, Up: false, Error: "read id: " + err.Error()}
	}
	if pid != 0 {
		return statService{Name: name, Addr: addr, Up: false, Error: fmt.Sprintf("unexpected packet id %d", pid)}
	}
	js, err := readString(br)
	if err != nil {
		return statService{Name: name, Addr: addr, Up: false, Error: "read json: " + err.Error()}
	}
	var m struct {
		Version struct {
			Name string `json:"name"`
		} `json:"version"`
		Players struct {
			Online int `json:"online"`
			Max    int `json:"max"`
		} `json:"players"`
		Description interface{} `json:"description"`
	}
	_ = json.Unmarshal([]byte(js), &m)
	desc := ""
	switch d := m.Description.(type) {
	case string:
		desc = d
	case map[string]interface{}:
		if t, ok := d["text"].(string); ok {
			desc = t
		}
	}
	return statService{Name: name, Addr: addr, Up: true, Latency: ms(time.Since(start)),
		Detail: fmt.Sprintf("%s, players %d/%d%s", m.Version.Name, m.Players.Online, m.Players.Max, func() string {
			if desc != "" {
				return ", \"" + desc + "\""
			}
			return ""
		}())}
}

func probeTCP(name, addr string, timeout time.Duration) statService {
	d, c, err := tcpDialMs(addr, timeout)
	if err != nil {
		return statService{Name: name, Addr: addr, Up: false, Error: err.Error()}
	}
	c.Close()
	return statService{Name: name, Addr: addr, Up: true, Latency: ms(d)}
}

// probeMind probes Mindustry with the legacy list-ping (0xFE 0x01) and times
// the full round trip: over the WireGuard path the connect itself already
// crosses the VPS↔PC link, so the reply latency is the real game-path RTT.
func probeMind(name, addr string, timeout time.Duration) statService {
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return statService{Name: name, Addr: addr, Up: false, Latency: ms(time.Since(start)), Error: err.Error()}
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte{0xFE, 0x01}); err != nil {
		return statService{Name: name, Addr: addr, Up: false, Latency: ms(time.Since(start)), Error: "ping write: " + err.Error()}
	}
	br := bufio.NewReader(c)
	buf := make([]byte, 32)
	n, rerr := br.Read(buf)
	if rerr != nil {
		return statService{Name: name, Addr: addr, Up: false, Latency: ms(time.Since(start)), Error: "no reply: " + rerr.Error()}
	}
	return statService{Name: name, Addr: addr, Up: true, Latency: ms(time.Since(start)),
		Detail: fmt.Sprintf("mindustry ping ok (%d bytes)", n)}
}

func (s *Server) gatherStats() statsResp {
	server, load := gatherSys()
	svcs := []statService{
		probeSSH("vps", "127.0.0.1:22", 2*time.Second),
		probeSSH("phone(ssh)", "127.0.0.1:8022", 2*time.Second),
		probeSSH("pc(ssh)", "10.66.0.2:22", 2*time.Second),
		probeMC("mc.rival-afk.com", "10.66.0.2:25565", 3*time.Second),
		probeMind("mind.rival-afk.com", "10.66.0.2:6567", 3*time.Second),
		probeTCP("internet(1.1.1.1)", "1.1.1.1:443", 2*time.Second),
	}
	peers := []map[string]interface{}{}
	if s.db != nil {
		rows, err := s.db.Query(`SELECT label, ip, updated_at FROM net_peers ORDER BY updated_at DESC`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var l, ip string
				var ts int64
				if rows.Scan(&l, &ip, &ts) == nil {
					peers = append(peers, map[string]interface{}{"label": l, "ip": ip, "seen": time.Unix(ts, 0).Format(time.RFC3339)})
				}
			}
		}
		var kc int
		s.db.QueryRow(`SELECT COUNT(*) FROM issued`).Scan(&kc)
		return statsResp{Time: time.Now().Unix(), Server: server, Load: load, Services: svcs, NetPeers: peers, Keys: kc}
	}
	return statsResp{Time: time.Now().Unix(), Server: server, Load: load, Services: svcs, NetPeers: peers}
}

func (s *Server) statsJSONHandler(w http.ResponseWriter, r *http.Request) {
	st := s.gatherStats()
	st.Domain = r.Host
	st.What = hostWhat(r.Host)
	writeJSON(w, 200, st)
}

const authStatusCSS = `
@font-face{font-family:Inter;font-style:normal;font-weight:400;font-display:swap;src:url(/console/inter-400.ttf) format('truetype')}
@font-face{font-family:Inter;font-style:normal;font-weight:500;font-display:swap;src:url(/console/inter-500.ttf) format('truetype')}
@font-face{font-family:Gasoek;font-style:normal;font-weight:400;font-display:swap;src:url(/console/gasoek.ttf) format('truetype')}
@font-face{font-family:'JetBrains Mono';font-style:normal;font-weight:400;font-display:swap;src:url(/console/jbmono-400.ttf) format('truetype')}
*{box-sizing:border-box}
body{margin:0;padding:28px 16px;background:#000;color:#e8e8e8;font:14px/1.55 Inter,system-ui,sans-serif}
.wrap{max-width:760px;margin:0 auto}
.head{text-align:center;margin:0 0 22px}
h1{font-family:Gasoek,Inter,sans-serif;font-weight:400;font-size:clamp(32px,9vw,56px);line-height:1;letter-spacing:.2em;text-indent:.2em;text-transform:uppercase;margin:0}
.sub{font-family:'JetBrains Mono',ui-monospace,monospace;font-size:12px;color:#888;letter-spacing:.06em;margin:10px 0 0}
.card{border:1px solid #2a2a2a;background:#050505;padding:16px 18px;margin:0 0 14px}
.card-title{font:500 11px 'JetBrains Mono',ui-monospace,monospace;text-transform:uppercase;letter-spacing:.16em;color:#8a8a8a;margin:0 0 10px}
.big{font-size:17px;font-weight:400;margin:0 0 12px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:baseline;margin:6px 0;font-family:'JetBrains Mono',ui-monospace,monospace;font-size:12.5px;color:#c8c8c8}
.k{color:#6a6a6a;text-transform:uppercase;font-size:10.5px;letter-spacing:.12em;min-width:88px}
.dim{font-family:'JetBrains Mono',ui-monospace,monospace;font-size:12px;color:#888;margin:0 0 12px}
.tablewrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-family:'JetBrains Mono',ui-monospace,monospace;font-size:12.5px}
td{border-top:1px solid #1e1e1e;padding:7px 10px;vertical-align:top;text-align:left;word-break:break-word}
tr:first-child td{border-top:0}
td:first-child{color:#fff;white-space:nowrap}
.lat{color:#8a8a8a}
.peers{margin:0;padding-left:18px;font-family:'JetBrains Mono',ui-monospace,monospace;font-size:12.5px;color:#b0b0b0}
.foot{text-align:center;margin:18px 0 0;font-family:'JetBrains Mono',ui-monospace,monospace;font-size:11.5px;color:#6a6a6a}
a{color:#e8e8e8}
a:hover{color:#000;background:#e8e8e8}
`

func (s *Server) rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("format") == "json" || strings.Contains(r.Header.Get("Accept"), "application/json") {
		s.statsJSONHandler(w, r)
		return
	}
	st := s.gatherStats()
	st.Domain = r.Host
	st.What = hostWhat(r.Host)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Refresh", "5")
	var b strings.Builder
	b.WriteString("<!doctype html><html lang=en><head><meta charset=utf-8>")
	b.WriteString("<meta name=viewport content=\"width=device-width,initial-scale=1\">")
	b.WriteString("<title>rival — auth</title><meta http-equiv=refresh content=5><style>")
	b.WriteString(authStatusCSS)
	b.WriteString("</style></head><body>")
	b.WriteString("<main class=wrap><header class=head><h1>rival</h1><p class=sub>auth API &middot; rsh gateway</p></header>")
	b.WriteString("<section class=card><div class=card-title>server</div>")
	fmt.Fprintf(&b, "<p class=big>%s</p>", st.What)
	fmt.Fprintf(&b, "<p class=row><span class=k>you reached</span><b>%s</b></p>", st.Domain)
	fmt.Fprintf(&b, "<p class=row><span class=k>host</span><span>%s &middot; %s &middot; %s &middot; up %ss</span></p>", st.Server["hostname"], st.Server["os"], st.Server["arch"], st.Server["uptime_s"])
	fmt.Fprintf(&b, "<p class=row><span class=k>kernel</span><span>%s &middot; cores %v &middot; load %v/%v/%v</span></p>",
		st.Server["kernel"], st.Load["cpu_count"], st.Load["load1"], st.Load["load5"], st.Load["load15"])
	fmt.Fprintf(&b, "<p class=row><span class=k>memory</span><span>%v / %v MB &middot; disk %v</span></p>",
		st.Load["mem_used_mb"], st.Load["mem_total_mb"], st.Load["disk"])
	b.WriteString("</section>")
	b.WriteString("<section class=card><div class=card-title>services</div>")
	b.WriteString("<p class=dim>ping: <b id=youvps>measuring…</b> = you&rarr;vps; each row shows <b>you&rarr;vps&rarr;device</b> (vps reports its own leg to the device)</p>")
	b.WriteString("<div class=tablewrap><table>")
	for _, sv := range st.Services {
		state := "<span style=color:#e5534b>DOWN</span>"
		if sv.Up {
			state = "<span style=color:#3fb950>UP</span> <span class=lat>" +
				strconv.FormatFloat(sv.Latency, 'f', 2, 64) + "ms</span>"
		}
		fmt.Fprintf(&b, "<tr data-svc=\"%s\" data-ms=\"%s\"><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			sv.Name, strconv.FormatFloat(sv.Latency, 'f', 3, 64), sv.Name, state, sv.Detail, sv.Error)
	}
	b.WriteString("</table></div></section>")
	if len(st.NetPeers) > 0 {
		b.WriteString("<section class=card><div class=card-title>net peers</div><ul class=peers>")
		for _, p := range st.NetPeers {
			fmt.Fprintf(&b, "<li>%v = %v (seen %v)</li>", p["label"], p["ip"], p["seen"])
		}
		b.WriteString("</ul></section>")
	}
	fmt.Fprintf(&b, "<p class=foot>refreshed %s &middot; json: <a href='/?format=json'>/?format=json</a></p></main>", time.Now().Format(time.RFC3339))
	b.WriteString("<script>(async()=>{const f=v=>Number(v).toFixed(2);const el=document.getElementById('youvps');const s=[];for(let i=0;i<3;i++){const t0=performance.now();try{await fetch('/healthz',{cache:'no-store'});}catch(e){}s.push(performance.now()-t0);}const rtt=Math.min(...s);el.textContent=f(rtt)+'ms';document.querySelectorAll('tr[data-ms]').forEach(tr=>{const base=parseFloat(tr.getAttribute('data-ms'))||0;const v=(tr.getAttribute('data-svc')==='vps')?rtt:rtt+base;const lat=tr.querySelector('.lat');if(lat){lat.textContent=f(v)+'ms';lat.title='you→vps '+f(rtt)+'ms + vps→device '+f(base)+'ms';}});})();</script>")
	b.WriteString("</body></html>")
	w.Write([]byte(b.String()))
}
