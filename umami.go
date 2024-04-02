package caddyumami

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Umami{})
	httpcaddyfile.RegisterHandlerDirective("umami", parseCaddyfile)
}

// Umami is a Caddy module that sends visitor information to the Umami Events REST API endpoint.
type Umami struct {
	EventEndpoint      string
	WebsiteUUID        string
	AllowedExtensions  map[string]bool
	ClientIPHeader     string
	DebugLogging       bool
	ReportAllResources bool
	TrustedIPHeader    string
	CookieConsent      string
	CookieResolution   string
}

// CaddyModule returns the Caddy module information.
func (Umami) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.umami",
		New: func() caddy.Module { return new(Umami) },
	}
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface.
func (p Umami) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Call the next handler in the chain
	err := next.ServeHTTP(w, r)
	if err != nil {
		return err
	}

	if p.CookieConsent != "" {
		cookie, err := r.Cookie(p.CookieConsent)
		if err == nil && cookie != nil && cookie.Value == "false" {
			return nil
		}
	}

	requestPath := strings.Clone(r.URL.Path)
	requestPath = strings.TrimSuffix(requestPath, "/index.html")
	if strings.HasSuffix(requestPath, "/") && r.URL.String() != "/" {
		requestPath = strings.TrimSuffix(requestPath, "/")
	}

	pathExt := path.Ext(requestPath)

	if !p.ReportAllResources {
		if !p.AllowedExtensions[pathExt] {
			return nil
		}
	}

	// Send visitor information to the Umami Events REST API endpoint
	go func() {
		payload := map[string]interface{}{
			"referrer": r.Referer(),
			"url":      requestPath,
			"website":  p.WebsiteUUID,
		}

		hostname, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			hostname = r.Host
		}
		payload["hostname"] = hostname

		payload["language"] = strings.Split(r.Header.Get("Accept-Language"), ",")[0]

		visitorIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			visitorIP = r.RemoteAddr
		}
		if p.TrustedIPHeader != "" {
			trustedIP := r.Header.Get(p.TrustedIPHeader)
			if net.ParseIP(trustedIP) != nil {
				visitorIP = trustedIP
			} else if p.DebugLogging {
				fmt.Printf("Invalid IP address provided by trusted IP header: %s\n", trustedIP)
			}
		}

		if p.CookieResolution != "" {
			cookie, err := r.Cookie(p.CookieResolution)
			if err != nil {
				if p.DebugLogging {
					fmt.Printf("Error getting resolution cookie: %v\n", err)
				}
			}

			// handle if cookie does not exist
			if cookie == nil {
				cookie = &http.Cookie{
					Name:  p.CookieResolution,
					Value: "",
				}
			}
			payload["resolution"] = cookie.Value
		}

		visitorInfo := map[string]interface{}{
			"payload": payload,
			"type":    "event",
		}

		body, err := json.Marshal(visitorInfo)
		if err != nil {
			fmt.Printf("Error marshaling visitor info: %v\n", err)
			return
		}

		client := &http.Client{}
		req, err := http.NewRequest("POST", p.EventEndpoint, bytes.NewBuffer(body))
		if err != nil {
			fmt.Printf("Error creating request: %v\n", err)
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", r.UserAgent())

		req.Header.Set("X-Forwarded-For", visitorIP)
		if p.ClientIPHeader != "" {
			req.Header.Set(p.ClientIPHeader, visitorIP)
		}

		if p.DebugLogging {
			fmt.Printf("IP: %s\n", visitorIP)
			fmt.Printf("User-Agent: %s\n", r.UserAgent())
			fmt.Printf("Body: %s\n", body)
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error sending visitor info: %v\n", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Error reading response body: %v\n", err)
				return
			}
			fmt.Printf("Error response from Umami API: %s\n", respBody)
			return
		}
	}()

	return nil
}

func (p *Umami) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "event_endpoint":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.EventEndpoint = d.Val()
			case "website_uuid":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.WebsiteUUID = d.Val()
			case "report_all_resources":
				p.ReportAllResources = d.Val() == "true"
			case "allowed_extensions":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.AllowedExtensions[d.Val()] = true // Add the current argument
				for _, ext := range d.RemainingArgs() {
					p.AllowedExtensions[ext] = true
				}
			case "client_ip_header":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.ClientIPHeader = d.Val()
			case "trusted_ip_header":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.TrustedIPHeader = d.Val()
			case "debug":
				p.DebugLogging = true
			case "cookie_consent":
				if !d.NextArg() {
					p.CookieConsent = "umami_consent"
				} else {
					p.CookieConsent = d.Val()
				}
			case "cookie_resolution":
				if !d.NextArg() {
					p.CookieResolution = "umami_resolution"
				} else {
					p.CookieResolution = d.Val()
				}

			default:
				return d.Errf("unknown option '%s'", d.Val())
			}
		}
	}

	// set default if p.AllowedExtensions is empty
	if len(p.AllowedExtensions) == 0 {
		p.AllowedExtensions = map[string]bool{
			"":      true,
			".htm":  true,
			".html": true,
			".php":  true,
		}
	}

	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var umami Umami
	umami.AllowedExtensions = make(map[string]bool)
	err := umami.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	if umami.DebugLogging {
		fmt.Printf("Event Endpoint: %s\n", umami.EventEndpoint)
		fmt.Printf("Website UUID: %s\n", umami.WebsiteUUID)
		fmt.Printf("Allowed Extensions: %v\n", umami.AllowedExtensions)
	}
	return umami, nil
}
