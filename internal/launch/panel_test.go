package launch

import "testing"

func TestPanelURL(t *testing.T) {
	for _, tc := range []struct{ origin, host, want string }{
		{"https://landing.sah.sh", "", "https://landing.sah.sh/panel"},
		{"https://panel.example/", "host-123", "https://panel.example/panel/gui/host-123"},
		{"http://localhost:5173", "h", "http://localhost:5173/panel/gui/h"},
		{"http://[::1]:5173", "h", "http://[::1]:5173/panel/gui/h"},
	} {
		u, err := PanelURL(tc.origin, tc.host)
		if err != nil || u.String() != tc.want {
			t.Fatalf("%s: %v %v", tc.origin, u, err)
		}
	}
}
func TestRejectUnsafeOrCredentialBearingLinks(t *testing.T) {
	for _, origin := range []string{"", "javascript:alert(1)", "file:///tmp/x", "http://panel.example", "https://user:password@panel.example", "https://panel.example?ticket=secret", "https://panel.example?", "https://panel.example/#token", "https://panel.example/path", "https://panel.example/%2f", "//panel.example"} {
		if _, err := PanelURL(origin, ""); err == nil {
			t.Errorf("accepted %q", origin)
		}
	}
	for _, host := range []string{"../secret", "..", ".", "host?token=x", "a/b", "a#b", "a b"} {
		if _, err := PanelURL("https://panel.example", host); err == nil {
			t.Errorf("accepted host %q", host)
		}
	}
}
