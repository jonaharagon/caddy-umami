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

// http.handlers.umami is a Caddy module that sends visitor information to Umami's Events REST API endpoint.
type Umami struct {
	// EventEndpoint defines the address of your Umami installation's send API endpoint.
	EventEndpoint string `json:"event_endpoint"`
	// WebsiteUUID is the UUID of the website you want to track.
	WebsiteUUID string `json:"website_uuid"`
	// AllowedExtensions is a map of page path extensions that should be reported to Umami.
	AllowedExtensions map[string]bool `json:"allowed_extensions,omitempty"`
	// ClientIPHeader is the header to use to send the client IP address to Umami.
	ClientIPHeader string `json:"my_field,omitempty"`
	// DebugLogging enables debug logging.
	DebugLogging bool `json:"debug,omitempty"`
	// ReportAllResources enables reporting of all resources (ignoring extension checks).
	ReportAllResources bool `json:"report_all_resources,omitempty"`
	// TrustedIPHeader is the header to use to get the client IP address from, behind a trusted reverse proxy.
	TrustedIPHeader string `json:"trusted_ip_header,omitempty"`
	// CookieConsent is a map of cookie-based consent settings.
	CookieConsent map[string]string `json:"cookie_consent,omitempty"`
	// CookieResolution is the name of the cookie that stores the visitor's screen resolution.
	CookieResolution string `json:"cookie_resolution,omitempty"`
	// DeviceDetection enables rudimentary device detection based on Sec-CH-UA-Mobile and Sec-CH-UA-Platform headers.
	DeviceDetection bool `json:"device_detection,omitempty"`
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

	if p.DebugLogging {
		fmt.Printf("Allowed? %d\n", p.GetAllowed(r))
	}

	// Check if analytics should be performed.
	if p.GetAllowed(r) == 0 {
		return nil
	}

	// Normalize request path.
	requestPath := strings.Clone(r.URL.Path)
	requestPath = strings.TrimSuffix(requestPath, "/index.html")
	if strings.HasSuffix(requestPath, "/") && r.URL.String() != "/" {
		requestPath = strings.TrimSuffix(requestPath, "/")
	}

	// Check if the request should be reported based on extension.
	pathExt := path.Ext(requestPath)
	if !p.ReportAllResources {
		if !p.AllowedExtensions[pathExt] {
			return nil
		}
	}

	// Send visitor information to the Umami Events REST API endpoint.
	go func() {
		// Get request query strings.
		queryStrings := r.URL.Query()
		queryString := queryStrings.Encode()
		if p.DebugLogging {
			fmt.Printf("Query Strings: %s\n", queryString)
		}

		// Normalize request path.
		if !strings.HasPrefix(requestPath, "/") {
			requestPath = "/" + requestPath
		}

		// Preserve query strings.
		if queryString != "" {
			requestPath = fmt.Sprintf("%s?%s", requestPath, queryString)
			if p.DebugLogging {
				fmt.Printf("Request Path: %s\n", requestPath)
			}
		}

		// Remove port from hostname.
		hostname, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			hostname = r.Host
		}

		// Create initial payload.
		payload := map[string]interface{}{
			"url":      requestPath,
			"website":  p.WebsiteUUID,
			"hostname": hostname,
		}

		// Add client information if allowed by cookie.
		if p.GetAllowed(r) == 1 {
			p.GetClientInfo(r, payload)
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

		visitorIP := p.GetClientIP(r)

		client := &http.Client{}
		req, err := http.NewRequest("POST", p.EventEndpoint, bytes.NewBuffer(body))
		if err != nil {
			fmt.Printf("Error creating request: %v\n", err)
			return
		}

		req.Header.Set("Content-Type", "application/json")

		// Use fake user agent if analytics is disabled.
		if p.GetAllowed(r) == 1 {
			req.Header.Set("User-Agent", r.UserAgent())
		} else {
			req.Header.Set("User-Agent", "Mozilla/5.0 (Unknown) Browser/1.0 (Anonymous Request)")
		}

		req.Header.Set("X-Forwarded-For", visitorIP)
		if p.ClientIPHeader != "" {
			req.Header.Set(p.ClientIPHeader, visitorIP)
		}

		// if p.DebugLogging {
		fmt.Printf("IP: %s\n", req.Header.Get("X-Forwarded-For"))
		fmt.Printf("User-Agent: %s\n", req.UserAgent())
		fmt.Printf("Body: %s\n", body)
		// }

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

// Check whether analytics should be performed based on cookie consent settings.
// 0 - no analytics
// 1 - all analytics
// 2 - only path analytics
func (p *Umami) GetAllowed(r *http.Request) int {
	if len(p.CookieConsent) != 0 {
		if p.CookieConsent["behavior"] == "path_only" {
			cookie, err := r.Cookie(p.CookieConsent["cookie"])
			if err == nil && cookie != nil && cookie.Value == "false" {
				return 2
			}
		} else if p.CookieConsent["behavior"] == "disable_all" {
			cookie, err := r.Cookie(p.CookieConsent["cookie"])
			if err == nil && cookie != nil && cookie.Value == "false" {
				return 0
			}
		}
	}
	return 1
}

// Get the client IP address from the request.
// If a trusted IP header is provided, use that instead.
// If the client opted-out, replace the IP address with a psuedo Class E IP address.
func (p *Umami) GetClientIP(r *http.Request) string {
	visitorIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		visitorIP = r.RemoteAddr
	}
	// get IP from header if provided
	if p.TrustedIPHeader != "" {
		trustedIP := r.Header.Get(p.TrustedIPHeader)
		if net.ParseIP(trustedIP) != nil {
			visitorIP = trustedIP
		} else if p.DebugLogging {
			fmt.Printf("Invalid IP address provided by trusted IP header: %s\n", trustedIP)
		}
	}
	// anonymize IP based on consent cookie
	if p.GetAllowed(r) != 1 {
		visitorIP = "240.16.0.1"
	}
	return visitorIP
}

// Get client information from the request.
func (p *Umami) GetClientInfo(r *http.Request, payload map[string]interface{}) {
	// Get language from Accept-Language header
	payload["language"] = strings.Split(r.Header.Get("Accept-Language"), ",")[0]

	// Get referrer
	if r.Referer() != "" {
		payload["referrer"] = r.Referer()
	}

	// Get screen resolution from cookie (if enabled)
	if p.CookieResolution != "" {
		cookie, err := r.Cookie(p.CookieResolution)
		if err != nil {
			if p.DebugLogging {
				fmt.Printf("Error getting resolution cookie: %v\n", err)
			}
		}
		if cookie != nil {
			payload["screen"] = cookie.Value
		}
	}

	// Set screen resolution based on Sec-CH-UA-Mobile and Sec-CH-UA-Platform headers
	// (if resolution cookie not set and device detection is enabled)
	if payload["screen"] == nil && p.DeviceDetection {
		mobile := r.Header.Get("Sec-CH-UA-Mobile")
		platform := r.Header.Get("Sec-CH-UA-Platform")

		if p.DebugLogging {
			fmt.Printf("Mobile: %s\n", mobile)
			fmt.Printf("Platform: %s\n", platform)
		}

		if mobile == "?1" {
			payload["screen"] = "400x800" // mobile
		} else if platform == `"Android"` {
			payload["screen"] = "900x600" // tablet
		} else if platform == `"Chrome OS"` {
			payload["screen"] = "1200x800" // laptop
		}
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
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
				p.ReportAllResources = true
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
				// defaults
				if !d.NextArg() {
					p.CookieConsent["behavior"] = "disable_all"
					p.CookieConsent["cookie"] = "umami_consent"
				} else {
					// if behavior specified
					if d.Val() == "disable_all" || d.Val() == "path_only" {
						p.CookieConsent["behavior"] = d.Val()
						if !d.NextArg() {
							// if cookie unspecified
							p.CookieConsent["cookie"] = "umami_consent"
						} else {
							// if behavior + cookie specified
							p.CookieConsent["cookie"] = d.Val()
						}
					} else {
						// if behavior unspecified + cookie specified
						p.CookieConsent["behavior"] = "disable_all"
						p.CookieConsent["cookie"] = d.Val()
					}
				}
			case "cookie_resolution":
				if !d.NextArg() {
					p.CookieResolution = "umami_resolution"
				} else {
					p.CookieResolution = d.Val()
				}
			case "device_detection":
				p.DeviceDetection = true

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

// MarshalCaddyfile implements caddyfile.Marshaler.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var umami Umami
	umami.AllowedExtensions = make(map[string]bool)
	umami.CookieConsent = make(map[string]string)
	err := umami.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	if umami.DebugLogging {
		fmt.Printf("Event Endpoint: %s\n", umami.EventEndpoint)
		fmt.Printf("Website UUID: %s\n", umami.WebsiteUUID)
		fmt.Printf("Reporting All Resources: %v\n", umami.ReportAllResources)
		fmt.Printf("Allowed Extensions: %v\n", umami.AllowedExtensions)
		fmt.Printf("Device Detection: %v\n", umami.DeviceDetection)
		fmt.Printf("Client IP Header: %s\n", umami.ClientIPHeader)
		fmt.Printf("Trusted IP Header: %s\n", umami.TrustedIPHeader)
		fmt.Printf("Cookie Consent Behavior: %v\n", umami.CookieConsent["behavior"])
		fmt.Printf("Cookie Consent Cookie: %s\n", umami.CookieConsent["cookie"])
		fmt.Printf("Cookie Resolution: %s\n", umami.CookieResolution)
		fmt.Printf("Debug Logging: %v\n", umami.DebugLogging)
	}
	return umami, nil
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*Umami)(nil)
	_ caddyfile.Unmarshaler       = (*Umami)(nil)
)
