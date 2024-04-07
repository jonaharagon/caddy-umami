<!-- markdownlint-disable MD010 -->
# Caddy Umami Plugin

A module for Caddy which sends HTTP request information to Umami as page view events. The data is sent directly from the web server to Umami's [`/api/send` endpoint](https://umami.is/docs/sending-stats) without requiring you to include any client-side JavaScript on your website. The visitor's IP is set via the `X-Forwarded-For` header or the header specified with **client_ip_header**, one of which should be [set as `CLIENT_IP_HEADER` in Umami](https://umami.is/docs/environment-variables).

## Config

```caddyfile
umami [<matcher>] {
	event_endpoint <endpoint>
	website_uuid <uuid>

	# the following are optional:

	allowed_extensions <extensions ...>
	client_ip_header <name>
	cookie_consent [path_only|disable_all] [<name>]
	cookie_resolution [<name>]
	device_detection
	trusted_ip_header <name>
	report_all_resources
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
- **cookie_consent** is the name of a cookie, if that cookie's value is `false` then this plugin will not run. If a name is not set, the default name is `umami_consent`.
- **cookie_resolution** is the name of a cookie whose value should be the user's screen resolution, for example `1920x1080`. It is your responsibility to set this cookie with client-side JavaScript (not provided). If this cookie is not set, device type will just be reported as unknown. If a name is not set, the default name is `umami_resolution`.
- **device_detection** can be enabled to set the sent screen resolution based on `Sec-CH-UA-Mobile`/`Sec-CH-UA-Platform`, for some rudimentary device detection without cookies. If this and `cookie_resolution` are both enabled, a screen resolution set by the cookie will take precedence.
- **trusted_ip_header** is the name of an incoming HTTP request header which contains the visitor's true IP, which will then be sent to Umami via the `X-Forwarded-For`. This may be useful if your Caddy server is behind a reverse proxy.
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
		device_detection
	}

	// ...

}
```

## Thanks

- Safing for [Plausible Feeder Traefik Plugin](https://github.com/safing/plausiblefeeder)

## License

Copyright &copy; 2024 Jonah Aragon

This source code is made available under the [MIT](LICENSE-MIT) **and** [Apache](LICENSE-Apache) licenses (i.e. you can pick which one to follow). This is because I generally prefer MIT and chose it first, but later noticed most of the Caddy ecosystem uses Apache 2.0 :smile:
