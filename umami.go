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
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Umami{})
	httpcaddyfile.RegisterHandlerDirective("umami", parseCaddyfile)
}

// A Caddy module which sends visitor information to Umami's Events REST API endpoint.
type Umami struct {
	// The address of your Umami installation's send API endpoint.
	EventEndpoint string `json:"event_endpoint"`
	// The UUID of the website you want to track.
	WebsiteUUID string `json:"website_uuid"`
	// A map of page path extensions that should be reported to Umami. You must include the leading dot.
	AllowedExtensions []string `json:"allowed_extensions,omitempty"`
	// The header to send the client IP address to Umami with.
	ClientIPHeader string `json:"client_ip_header,omitempty"`
	// Enables reporting of all resources (ignoring extension checks).
	ReportAllResources bool `json:"report_all_resources,omitempty"`
	// The header to use to get the client IP address from, behind a trusted reverse proxy.
	TrustedIPHeader string `json:"trusted_ip_header,omitempty"`
	// A map of cookie-based consent settings. Only the first value in the map is utilized currently.
	CookieConsent []CookieConsent `json:"cookie_consent,omitempty"`
	// The name of the cookie that stores the visitor's screen resolution.
	CookieResolution string `json:"cookie_resolution,omitempty"`
	// Enable rudimentary device detection based on Sec-CH-UA-Mobile and Sec-CH-UA-Platform headers.
	DeviceDetection bool `json:"device_detection,omitempty"`
	// Optional static metadata to include with each event via query string.
	StaticMetadata []StaticMetadata `json:"static_metadata,omitempty"`

	logger *zap.Logger
}

// Cookie-based consent settings.
type CookieConsent struct {
	// The name of the cookie that stores the consent setting.
	Name string `json:"name,omitempty"`
	// Can be "disable_all" to disable sending analytics if the cookie value is "false",
	// or "path_only" to send analytic data without client information (IP, user agent, etc.) if the cookie value is "false".
	// Defaults to "disable_all" if not specified.
	Behavior string `json:"behavior,omitempty"`
}

// Optional static metadata to include with each event via query string.
type StaticMetadata struct {
	// The key of the metadata.
	Key string `json:"key,omitempty"`
	// The value of the metadata.
	Value string `json:"value,omitempty"`
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
	p.logger.Debug("Umami middleware called")

	// Call the next handler in the chain
	err := next.ServeHTTP(w, r)
	if err != nil {
		return err
	}

	p.logger.Debug("Check if analytics should be performed:", zap.Int("allowed", p.GetAllowed(r)))
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
	found := false
	if !p.ReportAllResources {
		// check if the extension is in string slice
		for _, ext := range p.AllowedExtensions {
			if ext == pathExt {
				found = true
				break
			}
		}
		if found {
			p.logger.Debug("Path extension found", zap.String("path", requestPath))
		} else {
			p.logger.Debug("Path extension not found", zap.String("path", requestPath))
			return nil
		}
	}

	// Send visitor information to the Umami Events REST API endpoint.
	go func() {
		// Get request query strings.
		queryStrings := r.URL.Query()

		// Add optional metadata to query strings.
		for _, metadata := range p.StaticMetadata {
			queryStrings.Add(metadata.Key, metadata.Value)
		}

		// Encode query strings.
		queryString := queryStrings.Encode()
		p.logger.Debug("Query Strings", zap.String("queryStrings", queryString))

		// Normalize request path.
		if !strings.HasPrefix(requestPath, "/") {
			requestPath = "/" + requestPath
		}

		// Preserve query strings.
		if queryString != "" {
			requestPath = fmt.Sprintf("%s?%s", requestPath, queryString)
			p.logger.Debug("Request Path", zap.String("requestPath", requestPath))
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
			p.logger.Error("Error marshaling visitor info", zap.Error(err))
			return
		}

		visitorIP := p.GetClientIP(r)

		client := &http.Client{}
		req, err := http.NewRequest("POST", p.EventEndpoint, bytes.NewBuffer(body))
		if err != nil {
			p.logger.Error("Error creating request", zap.Error(err))
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

		p.logger.Debug("IP:", zap.String("IP", req.Header.Get("X-Forwarded-For")))
		p.logger.Debug("User-Agent:", zap.String("User-Agent", req.UserAgent()))
		p.logger.Debug("Body:", zap.Any("visitorInfo", visitorInfo))

		resp, err := client.Do(req)
		if err != nil {
			p.logger.Warn("Error sending visitor info", zap.Error(err))
			return
		} else {
			p.logger.Debug("Visitor info sent", zap.Int("status", resp.StatusCode))
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				p.logger.Warn("Error reading response body", zap.Error(err))
				return
			}
			p.logger.Warn("Error response from Umami API", zap.String("response", string(respBody)))
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
		if p.CookieConsent[0].Behavior == "path_only" {
			cookie, err := r.Cookie(p.CookieConsent[0].Name)
			if err == nil && cookie != nil && cookie.Value == "false" {
				return 2
			}
		} else if p.CookieConsent[0].Behavior == "disable_all" {
			cookie, err := r.Cookie(p.CookieConsent[0].Name)
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
		} else {
			p.logger.Debug("Invalid IP address provided by trusted IP header", zap.String("IP", trustedIP))
		}
	}
	// anonymize IP based on consent cookie
	if p.GetAllowed(r) != 1 {
		visitorIP = "240.16.0.1"
	}
	p.logger.Debug("Returning visitor IP to umami:", zap.String("IP", visitorIP))
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
			p.logger.Debug("Error getting resolution cookie", zap.Error(err))
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

		p.logger.Debug("Mobile", zap.String("mobile", mobile))
		p.logger.Debug("Platform", zap.String("platform", platform))

		if mobile == "?1" {
			payload["screen"] = "400x800" // mobile
		} else if platform == `"Android"` {
			payload["screen"] = "900x600" // tablet
		} else if platform == `"Chrome OS"` {
			payload["screen"] = "1200x800" // laptop
		}
	}
}

// Provision logging for module
func (p *Umami) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger()
	return nil
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
				p.AllowedExtensions = append(p.AllowedExtensions, d.Val()) // Add the current argument
				p.AllowedExtensions = append(p.AllowedExtensions, d.RemainingArgs()...)
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
			case "cookie_consent":
				// defaults
				if !d.NextArg() {
					p.CookieConsent = append(p.CookieConsent, CookieConsent{Name: "umami_consent", Behavior: "disable_all"})
				} else {
					// if behavior specified
					if d.Val() == "disable_all" || d.Val() == "path_only" {
						behavior := d.Val()
						if !d.NextArg() {
							// if cookie unspecified
							p.CookieConsent = append(p.CookieConsent, CookieConsent{Name: "umami_consent", Behavior: behavior})
						} else {
							// if behavior + cookie specified
							p.CookieConsent = append(p.CookieConsent, CookieConsent{Name: d.Val(), Behavior: behavior})
						}
					} else {
						// if behavior unspecified + cookie specified
						p.CookieConsent = append(p.CookieConsent, CookieConsent{Name: d.Val(), Behavior: "disable_all"})
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
			case "static_metadata":
				Metadata, err := ParseCaddyfileStaticMetadata(d)
				if err != nil {
					return err
				}
				p.StaticMetadata = Metadata

			default:
				return d.Errf("unknown option '%s'", d.Val())
			}
		}
	}

	// set default if p.AllowedExtensions is empty
	if len(p.AllowedExtensions) == 0 {
		p.AllowedExtensions = []string{"", ".htm", ".html", ".php"}
	}

	return nil
}

func ParseCaddyfileStaticMetadata(d *caddyfile.Dispenser) ([]StaticMetadata, error) {
	var metadata []StaticMetadata

	// Allow for options formatted as:
	//     static_metadata key value
	if d.NextArg() {
		key := d.Val()
		if !d.NextArg() {
			return nil, d.ArgErr()
		}
		value := d.Val()
		metadata = append(metadata, StaticMetadata{Key: key, Value: value})
		return metadata, nil
	}

	// Allow for options formatted as:
	//     static_metadata {
	//         key value
	//		     key value
	//         ...
	//     }
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		key := d.Val()
		if !d.NextArg() {
			return nil, d.ArgErr()
		}
		value := d.Val()
		metadata = append(metadata, StaticMetadata{Key: key, Value: value})
	}
	return metadata, nil
}

// MarshalCaddyfile implements caddyfile.Marshaler.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var umami Umami
	umami.AllowedExtensions = []string{}
	umami.CookieConsent = []CookieConsent{}
	err := umami.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return umami, nil
}

func (p *Umami) Validate() error {
	if p.EventEndpoint == "" {
		return fmt.Errorf("no event endpoint provided")
	}
	if p.WebsiteUUID == "" {
		return fmt.Errorf("no website UUID provided")
	}
	p.logger.Debug("Event Endpoint: " + p.EventEndpoint)
	p.logger.Debug("Website UUID: " + p.WebsiteUUID)
	p.logger.Debug("Allowed Extensions: " + fmt.Sprint(p.AllowedExtensions))
	p.logger.Debug("Client IP Header: " + p.ClientIPHeader)
	p.logger.Debug("Trusted IP Header: " + p.TrustedIPHeader)
	p.logger.Debug("Report All Resources: " + fmt.Sprint(p.ReportAllResources))
	p.logger.Debug("Cookie Consent: " + fmt.Sprint(p.CookieConsent))
	p.logger.Debug("Cookie Resolution: " + p.CookieResolution)
	p.logger.Debug("Device Detection: " + fmt.Sprint(p.DeviceDetection))
	p.logger.Debug("Static Metadata: " + fmt.Sprint(p.StaticMetadata))
	p.logger.Info("Umami middleware validated")
	return nil
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*Umami)(nil)
	_ caddyfile.Unmarshaler       = (*Umami)(nil)
	_ caddy.Provisioner           = (*Umami)(nil)
	_ caddy.Validator             = (*Umami)(nil)
)
