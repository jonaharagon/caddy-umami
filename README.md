<!-- markdownlint-disable MD010 -->
# Caddy Umami Plugin

A module for Caddy which sends HTTP request information to Umami as page view events. The data is sent directly from the web server to Umami's [`/api/send` endpoint](https://umami.is/docs/sending-stats) without requiring you to include any client-side JavaScript on your website. The visitor's IP is set via the `X-Forwarded-For` header, one of which should be [set as `CLIENT_IP_HEADER` in Umami](https://umami.is/docs/environment-variables).

## Config

```caddyfile
umami [<matcher>] {
	event_endpoint <endpoint>
	website_uuid <uuid>

	# the following are optional:

	allowed_extensions <extensions ...>
	client_ip_header <name>
	report_all_resources
	debug
}
```

- **event_endpoint** is the address of your Umami installation's send API endpoint
- **website_uuid** is the UUID of the website from your Umami dashboard
- **allowed_extensions** is a list of extensions which indicate valid content.
  - Make sure to include `""` in this list if you want to track URLs which don't end in a file extension, such as `/` or `/about-us`
  - If unspecified, the default list of extensions is:
    - No extension
    - `.htm`
    - `.html`
    - `.php`
- **client_ip_header** is the name of an HTTP header which will be sent to Umami **alongside** `X-Forwarded-For`, which contains the visitor's IP address.
- **report_all_resources** can be included to report **all** requests to Umami, overriding allowed_extensions. By default, only requests with certain extensions are reported. This may be especially useful when using this module with a matcher.

### Full Example

You should specify the order of the `umami` directive in your global options, otherwise the `umami` block has to be defined inside a `route` block.

```caddyfile
{
	# see: https://caddyserver.com/docs/caddyfile/directives#directive-order
	order umami after route
}

example.com {
	umami {
		event_endpoint "https://umami.example.com/api/send"
		website_uuid "4fa2c16a-6c0f-488f-986f-bc26d90c76d1"
		allowed_extensions "" .html .htm .php
		client_ip_header X-Real-IP
	}

	// ...

}
```

## Thanks

- Safing for [Plausible Feeder Traefik Plugin](https://github.com/safing/plausiblefeeder)
