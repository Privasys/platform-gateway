package routetable

import "testing"

// An alias route stands an adopter's hostname in front of an app. Everything
// upstream must keep the canonical name, so these two helpers decide what the
// enclave is told on every terminated connection.
func TestAliasHelpers(t *testing.T) {
	cases := []struct {
		name     string
		route    Route
		isAlias  bool
		upstream string
	}{
		{
			name:     "ordinary platform route",
			route:    Route{SNI: "harness.apps.privasys.org", Upstream: "10.0.0.1:443"},
			isAlias:  false,
			upstream: "harness.apps.privasys.org",
		},
		{
			name:     "adopter hostname",
			route:    Route{SNI: "harness.example.com", Canonical: "harness.apps.privasys.org"},
			isAlias:  true,
			upstream: "harness.apps.privasys.org",
		},
		{
			// A feed that echoes the hostname into canonical must not turn
			// a platform route into an alias: it would force terminate mode
			// and block RA-TLS clients from splicing.
			name:     "canonical equal to the hostname is not an alias",
			route:    Route{SNI: "harness.apps.privasys.org", Canonical: "harness.apps.privasys.org"},
			isAlias:  false,
			upstream: "harness.apps.privasys.org",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.route.IsAlias(); got != tc.isAlias {
				t.Errorf("IsAlias() = %v, want %v", got, tc.isAlias)
			}
			if got := tc.route.UpstreamName(); got != tc.upstream {
				t.Errorf("UpstreamName() = %q, want %q", got, tc.upstream)
			}
		})
	}
}
