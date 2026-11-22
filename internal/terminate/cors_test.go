package terminate

import "testing"

func TestParseWildcardOrigin(t *testing.T) {
	cases := []struct {
		spec    string
		wantSuf string
		wantOK  bool
	}{
		{"*.privasys.org", "privasys.org", true},
		{"*.privasys.id", "privasys.id", true},
		{"https://*.privasys.org", "privasys.org", true},
		{"https://*.privasys.org:8443", "privasys.org", true},
		{"https://*.privasys.org/path", "privasys.org", true},
		{"*.PRIVASYS.org", "privasys.org", true},
		{"*.", "", false},
		{"https://chat.privasys.org", "", false},
		{"chat.privasys.org", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := parseWildcardOrigin(tc.spec)
		if ok != tc.wantOK || got != tc.wantSuf {
			t.Errorf("parseWildcardOrigin(%q) = (%q, %v), want (%q, %v)",
				tc.spec, got, ok, tc.wantSuf, tc.wantOK)
		}
	}
}

func TestIsAllowedOrigin(t *testing.T) {
	h := New(Options{
		CORSOrigins: []string{
			"https://chat.test.privasys.org",
			"*.privasys.org",
			"*.privasys.id",
		},
	})

	allowed := []string{
		"https://chat.test.privasys.org",
		"https://chat.privasys.org",
		"https://app.privasys.org",
		"http://privasys.org",
		"https://foo.bar.privasys.org",
		"https://wallet.privasys.id",
		"https://privasys.id:8443",
	}
	for _, o := range allowed {
		if !h.isAllowedOrigin(o) {
			t.Errorf("expected origin %q to be allowed", o)
		}
	}

	denied := []string{
		"",
		"https://privasys.org.evil.com",
		"https://evil.com",
		"https://idprivasys.id",
		"https://privasys.io",
	}
	for _, o := range denied {
		if h.isAllowedOrigin(o) {
			t.Errorf("expected origin %q to be denied", o)
		}
	}
}

func TestWildcardOriginSkipsAppDomains(t *testing.T) {
	h := New(Options{
		CORSOrigins: []string{
			"*.privasys.org",
			"https://drive.apps.privasys.org",
		},
		AppDomains: []string{"tenants.example.org"},
	})
	allowed := []string{
		"https://chat.privasys.org",
		"https://developer.test.privasys.org",
		"https://apps.privasys.org",       // the app domain itself is not an app
		"https://drive.apps.privasys.org", // exact entries keep working
	}
	for _, o := range allowed {
		if !h.isAllowedOrigin(o) {
			t.Errorf("expected origin %q to be allowed", o)
		}
	}
	denied := []string{
		"https://evil.apps.privasys.org",
		"https://evil.apps-test.privasys.org",
		"https://evil.apps.test.privasys.org",
		"https://a.b.apps.privasys.org",
	}
	for _, o := range denied {
		if h.isAllowedOrigin(o) {
			t.Errorf("expected origin %q to be denied", o)
		}
	}

	// A wildcard at the app domain itself is an explicit choice to allow
	// its apps; a configured app domain is honoured like the convention.
	h = New(Options{
		CORSOrigins: []string{"*.apps.privasys.org", "*.example.org"},
		AppDomains:  []string{"tenants.example.org"},
	})
	if !h.isAllowedOrigin("https://drive.apps.privasys.org") {
		t.Error("*.apps.privasys.org must match its apps")
	}
	if !h.isAllowedOrigin("https://www.example.org") {
		t.Error("*.example.org must match its own sites")
	}
	if h.isAllowedOrigin("https://x.tenants.example.org") {
		t.Error("*.example.org must not match a configured app domain's apps")
	}
}
