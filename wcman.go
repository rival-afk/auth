package main

// wcman — wildcard-сертификат *.rival-afk.com руками через x/crypto/acme
// (свежий autocert умеет только http-01/tls-alpn-01, DNS-01 выпилили).
// Нужен, чтобы ЛЮБОЙ субдомен *.rival-afk.com (wildcard DNS ведёт на vps)
// отдавал валидный TLS и попадал на заглушку rival-afk.com/not-found.
// Токен CF (Zone.DNS:Edit) — auth.json "dns_cf_token"; без него менеджер
// не создаётся и всё работает как раньше (новые субдомены = TLS-ошибка).

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

const wcDomain = "*.rival-afk.com"

type wildcardMan struct {
	dns  *cfDNS
	dir  string // каталог кэша (account key, cert, key)
	name string // dns-зона: rival-afk.com

	mu       sync.Mutex
	crt      *tls.Certificate
	notAfter time.Time
}

func newWildcardMan(cfg *Config) *wildcardMan {
	if cfg.DNSCFToken == "" {
		return nil
	}
	return &wildcardMan{
		dns:  &cfDNS{token: cfg.DNSCFToken},
		dir:  filepath.Join(cfg.ACMECache, "wildcard"),
		name: zoneOf(wcDomain),
	}
}

// get — сертификат для TLS GetCertificate fallback; nil, если не готов.
func (w *wildcardMan) get() *tls.Certificate {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.crt
}

func (w *wildcardMan) start(ctx context.Context) {
	// первый заход сразу (в фоне, чтобы не задержать старт сервера)
	go func() {
		for i := 0; i < 3; i++ {
			if err := w.ensure(ctx); err == nil {
				w.watch(ctx)
				return
			} else {
				log.Printf("wildcard cert: %v (retry 5 min)", err)
				select {
				case <-time.After(5 * time.Minute):
				case <-ctx.Done():
					return
				}
			}
		}
	}()
}

// watch — фоновое обновление: раз в сутки проверяем, жив ли сертификат.
func (w *wildcardMan) watch(ctx context.Context) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		w.mu.Lock()
		na := w.notAfter
		w.mu.Unlock()
		// LE-сертификаты на 90 дней; обновляем за 30
		if time.Until(na) > 30*24*time.Hour {
			continue
		}
		if err := w.ensure(ctx); err != nil {
			log.Printf("wildcard cert renew: %v", err)
		} else {
			log.Printf("wildcard cert renewed (until %s)", w.notAfter.Format("2006-01-02"))
		}
	}
}

func (w *wildcardMan) ensure(ctx context.Context) error {
	if err := os.MkdirAll(w.dir, 0700); err != nil {
		return err
	}
	// 1) готовый сертификат из кэша?
	crt, na, err := loadWC(w.dir)
	if err == nil && time.Until(na) > 30*24*time.Hour {
		w.mu.Lock()
		w.crt, w.notAfter = crt, na
		w.mu.Unlock()
		return nil
	}
	// 2) выпуск через ACME DNS-01
	if err := w.issue(ctx); err != nil {
		return err
	}
	crt, na, err = loadWC(w.dir)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.crt, w.notAfter = crt, na
	w.mu.Unlock()
	return nil
}

// issue — полный ACME-цикл: аккаунт → order → DNS-01 → CSR → сертификат.
func (w *wildcardMan) issue(ctx context.Context) error {
	acctKey, err := loadOrGenECDSA(filepath.Join(w.dir, "account.key"))
	if err != nil {
		return err
	}
	c := &acme.Client{Key: acctKey}
	if _, err := c.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil {
		return err
	}
	order, err := c.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: wcDomain}})
	if err != nil {
		return err
	}
	zone := w.name
	name := "_acme-challenge." + zone
	for _, azURL := range order.AuthzURLs {
		az, err := c.GetAuthorization(ctx, azURL)
		if err != nil {
			return err
		}
		for _, chal := range az.Challenges {
			if chal.Type != "dns-01" {
				continue
			}
			val, err := c.DNS01ChallengeRecord(chal.Token)
			if err != nil {
				return err
			}
			if err := w.dns.addTXT(ctx, zone, name, val); err != nil {
				return err
			}
			defer w.dns.delTXT(context.WithoutCancel(ctx), zone, name, val)
			if _, err := c.Accept(ctx, chal); err != nil {
				return err
			}
			if _, err := c.WaitAuthorization(ctx, chal.URI); err != nil {
				return err
			}
		}
	}
	// порядок готов к CSR
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tpl := &x509.CertificateRequest{DNSNames: []string{wcDomain}}
	csrd, err := x509.CreateCertificateRequest(rand.Reader, tpl, certKey)
	if err != nil {
		return err
	}
	der, _, err := c.CreateCertFromOrder(ctx, order, csrd, true)
	if err != nil {
		return err
	}
	// сохраняем: цепочка + ключ
	if err := writeChain(w.dir, der); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(w.dir, "cert.key"), keyPEM, 0600); err != nil {
		return err
	}
	log.Printf("wildcard cert issued for %s", wcDomain)
	return nil
}

// loadWC читает cert.pem (цепочка) + cert.key и возвращает готовый tls.Certificate.
func loadWC(dir string) (*tls.Certificate, time.Time, error) {
	cp, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		return nil, time.Time{}, err
	}
	kp, err := os.ReadFile(filepath.Join(dir, "cert.key"))
	if err != nil {
		return nil, time.Time{}, err
	}
	crt, err := tls.X509KeyPair(cp, kp)
	if err != nil {
		return nil, time.Time{}, err
	}
	leaf, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return nil, time.Time{}, err
	}
	return &crt, leaf.NotAfter, nil
}

// writeChain пишет PEM-цепочку (лист + промежуточные).
func writeChain(dir string, der [][]byte) error {
	var buf strings.Builder
	for _, d := range der {
		buf.WriteString(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})))
	}
	return os.WriteFile(filepath.Join(dir, "cert.pem"), []byte(buf.String()), 0600)
}

// loadOrGenECDSA — ключ аккаунта ACME: читает PEM ECDSA P-256 или генерит новый.
func loadOrGenECDSA(path string) (crypto.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
	blk:
		for {
			block, rest := pem.Decode(b)
			if block == nil {
				break blk
			}
			if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return k, nil
			}
			b = rest
		}
		return nil, os.ErrInvalid
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	d, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: d}), 0600); err != nil {
		return nil, err
	}
	return k, nil
}
