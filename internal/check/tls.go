package check

func (r *Result) tlsEnvironment(server, path, key, value string) {
	if key == "NODE_TLS_REJECT_UNAUTHORIZED" && value == "0" {
		r.finding(server, path, "tls-verification-disabled", "TLS certificate verification is explicitly disabled")
	}
}
