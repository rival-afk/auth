package main

// Работа с DNS-записями Cloudflare (API v4) для DNS-01 challenge.
// Токен (Zone.DNS:Edit зоны rival-afk.com) — в auth.json "dns_cf_token".
// Используется только wildcard-менеджером (wcman.go): autocert в свежем
// x/crypto DNS-01 не умеет.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type cfDNS struct {
	token string

	mu  sync.Mutex
	zid string // id зоны rival-afk.com, лениво
}

func (p *cfDNS) api(ctx context.Context, method, path string, body interface{}) (map[string]interface{}, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.cloudflare.com/client/v4"+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("cf api: bad body: %v", err)
	}
	if ok, _ := out["success"].(bool); !ok {
		msg := strings.TrimSpace(string(b))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return out, fmt.Errorf("cf api %s %s: %s", method, path, msg)
	}
	return out, nil
}

// zoneOf — имя DNS-зоны: последние две метки fqdn (rival-afk.com).
func zoneOf(domain string) string {
	d := strings.TrimPrefix(domain, "*.")
	parts := strings.Split(d, ".")
	if n := len(parts); n >= 2 {
		return strings.Join(parts[n-2:], ".")
	}
	return d
}

// zoneID — id зоны по имени; считается лениво и кэшируется.
func (p *cfDNS) zoneID(ctx context.Context, zone string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.zid != "" {
		return p.zid, nil
	}
	out, err := p.api(ctx, http.MethodGet, "/zones?name="+zone, nil)
	if err != nil {
		return "", err
	}
	res, _ := out["result"].([]interface{})
	if len(res) == 0 {
		return "", fmt.Errorf("cf: zone %s not found", zone)
	}
	m, _ := res[0].(map[string]interface{})
	id, _ := m["id"].(string)
	if id == "" {
		return "", fmt.Errorf("cf: empty zone id")
	}
	p.zid = id
	return id, nil
}

// addTXT создаёт TXT-запись и даёт CF несколько секунд на распространение.
func (p *cfDNS) addTXT(ctx context.Context, zone, name, value string) error {
	zid, err := p.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	if _, err := p.api(ctx, http.MethodPost, "/zones/"+zid+"/dns_records", map[string]interface{}{
		"type":    "TXT",
		"name":    name,
		"content": value,
		"ttl":     60,
	}); err != nil {
		return err
	}
	time.Sleep(5 * time.Second)
	return nil
}

// delTXT удаляет TXT-записи с данным значением (если остались).
func (p *cfDNS) delTXT(ctx context.Context, zone, name, value string) {
	zid, err := p.zoneID(ctx, zone)
	if err != nil {
		return
	}
	out, err := p.api(ctx, http.MethodGet,
		"/zones/"+zid+"/dns_records?type=TXT&name="+name+"&per_page=100", nil)
	if err != nil {
		return
	}
	res, _ := out["result"].([]interface{})
	for _, r := range res {
		m, _ := r.(map[string]interface{})
		if m["content"] == value {
			if id, _ := m["id"].(string); id != "" {
				p.api(ctx, http.MethodDelete, "/zones/"+zid+"/dns_records/"+id, nil)
			}
		}
	}
}
