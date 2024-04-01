<!-- markdownlint-disable MD010 -->
# Caddy Umami Plugin

A module for Caddy which sends HTTP request information to Umami as page view events. The data is sent directly from the web server to Umami without requiring you to include any client-side JavaScript on your website. The visitor's IP is set via the `X-Forwarded-For` and `X-Real-IP` headers, one of which should be [set as `CLIENT_IP_HEADER` in Umami](https://umami.is/docs/environment-variables).

## Config

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

		# the following are optional:

		# report every single request to Umami
		# by default, only requests with certain extensions are reported
		report_all_resources

		# a list of file extensions that should be reported
		# by default .html, .htm, and requests with no file extension are reported
		# be sure to include "" if you want paths like /about-us without an extension to be reported
		allowed_extensions "" .html .htm

		# very verbose logging of all reported requests
		verbose
	}

	// ...

}
```

## Thanks

- Safing for [Plausible Feeder Traefik Plugin](https://github.com/safing/plausiblefeeder)
