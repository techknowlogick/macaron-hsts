package hsts // import "src.techknowlogick.com/macaron-hsts"

import (
	"fmt"
	"net/http"

	"gopkg.in/macaron.v1"
)

type HSTSOptions struct {
	MaxAge     int
	Subdomains bool
	Preload    bool
}

func HSTSHeader(options *HSTSOptions) macaron.Handler {
	return func(res http.ResponseWriter, req *http.Request, c *macaron.Context) {
		header := fmt.Sprintf("max-age=%d", options.MaxAge)
		if options.Subdomains {
			header = fmt.Sprintf("%s; includeSubDomains", header)
		}
		if options.Preload {
			header = fmt.Sprintf("%s; preload", header)
		}
		res.Header().Set("Strict-Transport-Security", header)
	}
}
