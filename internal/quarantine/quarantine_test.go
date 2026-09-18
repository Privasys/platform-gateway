package quarantine

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
)

func TestWantsHTML(t *testing.T) {
	cases := map[string]bool{
		"":                            false,
		"*/*":                         false,
		"application/json":            false,
		"application/json, text/html": false,
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8": true,
		"*/*, text/html": true,
		"TEXT/HTML":      true,
	}
	for accept, want := range cases {
		if got := WantsHTML(accept); got != want {
			t.Errorf("WantsHTML(%q) = %v, want %v", accept, got, want)
		}
	}
}

func TestWriteHTTPHead(t *testing.T) {
	req, _ := http.NewRequest(http.MethodHead, "https://app.example.com/", nil)
	extra := http.Header{}
	extra.Set("Vary", "Origin")
	var b strings.Builder
	if err := WriteHTTP(&b, req, extra); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(b.String())), req)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Vary"); got != "Origin, Accept" {
		t.Errorf("Vary = %q", got)
	}
	if strings.Contains(b.String(), ErrorCode) {
		t.Error("HEAD response carries a body")
	}
}
