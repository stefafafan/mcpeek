package check

import (
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

var variable = regexp.MustCompile(`^(\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$\{env:[A-Za-z_][A-Za-z0-9_]*\}|\$\{input:[A-Za-z_][A-Za-z0-9_-]*\})$`)

func credentialKey(key string) bool {
	key = strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
	switch key {
	case "AUTHORIZATION", "PROXY_AUTHORIZATION", "COOKIE", "SET_COOKIE", "PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY", "ACCESS_KEY", "PRIVATE_KEY":
		return true
	}
	for _, suffix := range []string{"_TOKEN", "_SECRET", "_PASSWORD", "_PASSWD", "_API_KEY", "_APIKEY", "_ACCESS_KEY", "_ACCESS_KEY_ID", "_PRIVATE_KEY"} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}
func literal(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, prefix := range []string{"Bearer ", "Basic "} {
		if strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)) {
			value = strings.TrimSpace(value[len(prefix):])
			break
		}
	}
	return !variable.MatchString(value)
}
func (r *Result) credential(server, path, key, value string) {
	if credentialKey(key) && literal(value) {
		r.finding(server, path, "secret-literal", "suspected literal credential")
	}
}
func (r *Result) remote(server, path, endpoint string) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || strings.ContainsAny(u.Host, "${}") {
		r.Problem(path, server, "unassessed", "endpoint must be a literal HTTP or HTTPS URL")
		return
	}
	if u.User != nil {
		if password, ok := u.User.Password(); ok && literal(password) {
			r.finding(server, path, "secret-literal", "suspected literal URL credential")
		}
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		r.Problem(path, server, "unassessed", "unsupported URL query syntax")
	} else {
		for _, k := range sortedKeys(query) {
			for _, v := range query[k] {
				r.credential(server, path, k, v)
			}
		}
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	loopback := host == "localhost"
	if ip, err := netip.ParseAddr(host); err == nil {
		loopback = ip.Unmap().IsLoopback()
	}
	if u.Scheme == "http" && !loopback {
		r.finding(server, path, "remote-http", "remote endpoint uses plaintext HTTP")
	}
}
