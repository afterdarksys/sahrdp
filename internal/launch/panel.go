// Package launch builds credential-free links to the existing SAH GUI panel.
package launch

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var hostID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`)

// PanelURL accepts an explicit panel origin, not the isolated GUI media origin.
// The browser owns authentication and ticket issuance. Empty host opens the
// fleet selector; a host ID opens its app selector, never an arbitrary command.
func PanelURL(origin, host string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return nil, errors.New("Enter a panel origin such as https://landing.sah.sh")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !(strings.EqualFold(u.Hostname(), "localhost") || ip != nil && ip.IsLoopback()) {
			return nil, errors.New("Use HTTPS; HTTP is allowed only for local development")
		}
	}
	if host != "" && (!hostID.MatchString(host) || host == "." || host == "..") {
		return nil, errors.New("Enter a host ID, or leave it blank to choose a host in the panel")
	}
	u.Path = "/panel"
	if host != "" {
		u.Path += "/gui/" + host
	}
	return u, nil
}
