import Config

# Advertise the instance as HTTPS via the Caddy gateway.
config :pleroma, Pleroma.Web.Endpoint,
  url: [host: System.get_env("DOMAIN", "pleroma.test"), scheme: "https", port: 443]

# Trust the fedbox Caddy internal CA so federation over HTTPS works inside the
# docker network.
cacertfile = System.get_env("FEDBOX_CACERTFILE", "/caddy/pki/authorities/local/root.crt")

config :pleroma, :http,
  adapter: [
    ssl_options: [
      verify: :verify_peer,
      cacertfile: cacertfile,
      depth: 20,
      reuse_sessions: false,
      log_level: :warning,
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
    ]
  ]

# Keep it permissive for local testing.
config :pleroma, :instance,
  registrations_open: true

# Disable CAPTCHA for fedbox user seeding / smoke tests.
config :pleroma, Pleroma.Captcha, enabled: false

