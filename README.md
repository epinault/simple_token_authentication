# SimpleTokenAuthentication

[![Build Status](https://github.com/epinault/simple_token_authentication/actions/workflows/ci.yml/badge.svg)](https://github.com/epinault/simple_token_authentication/actions/workflows/ci.yml) [![Hex.pm](https://img.shields.io/hexpm/v/simple_token_authentication.svg)](https://hex.pm/packages/simple_token_authentication) [![Documentation](https://img.shields.io/badge/documentation-gray)](https://hexdocs.pm/simple_token_authentication)
[![Total Download](https://img.shields.io/hexpm/dt/simple_token_authentication.svg)](https://hex.pm/packages/simple_token_authentication)
[![License](https://img.shields.io/hexpm/l/simple_token_authentication.svg)](https://github.com/epinault/simple_token_authentication/blob/master/LICENSE.md)
## Usage
### Phoenix Integration

Inside `web/router.ex` file, add plug to your pipeline like so:

```elixir
defmodule MyApp.Router
  use Phoenix.Router

  pipeline :api do
    plug SimpleTokenAuthentication
  end

  scope "/", MyApp do
    pipe_through :api
    get "/hello", HelloController, :hello
  end
end
```
## Installation

1. Add `simple_token_authentication` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [{:simple_token_authentication, "~> 1.1"}]
end
```

2. Ensure `simple_token_authentication` is started before your application:

```elixir
def application do
  [applications: [:simple_token_authentication]]
end
```

3. Configure your token in `config.exs`:
```elixir
config :simple_token_authentication,
  token: "your-token-here",
  service_tokens: [
    service_a: "service-a-token",
    service_b: "service-b-token"
  ]
```

4. Configure your connecting application to pass a token in the `authorization` header, either bare or with the `Bearer` scheme:
```elixir
put_header("authorization", "your-token-here")
put_header("authorization", "Bearer your-token-here")
```

## Header and scheme

By default the plug reads the `authorization` header and accepts either a bare token or `Bearer <token>` (scheme name matched case-insensitively). Both can be changed per plug:

```elixir
# Require the Bearer scheme
plug SimpleTokenAuthentication, scheme: :bearer

# Only accept a bare token (behaviour of versions before 1.1)
plug SimpleTokenAuthentication, scheme: :none

# Read the token from a different header
plug SimpleTokenAuthentication, header: "x-api-key"
```

`scheme` must be one of `:any` (default), `:bearer` or `:none`.

## Realm

Optionally, you can add a realm to the simple auth. This allows services to use the plug multiple times with different realms
For example:

Configure your token under a named realm in `config.exs`:
```elixir
config :simple_token_authentication,
  another_realm: [
    service_tokens: [
      service_a: "service-a-token",
      service_b: "service-b-token"
    ]
  ]
```

Pass that name when configuring the plug:
```elixir
defmodule MyApp.Router
  use Phoenix.Router

  pipeline :api do
    plug SimpleTokenAuthentication, auth_realm: :another_realm
  end

  scope "/", MyApp do
    pipe_through :api
    get "/hello", HelloController, :hello
  end
end
```

## Restricting a route to specific services

A realm decides which tokens exist; by default every service in the realm is accepted wherever the plug is used. Pass `services` to narrow a pipeline or controller to some of them. Tokens stay configured once, in the realm:

```elixir
config :simple_token_authentication,
  partners: [
    service_tokens: [
      acme: "acme-token",
      globex: "globex-token"
    ]
  ]
```

For a group of routes, use a dedicated pipeline. Each scope lists its own pipelines, since `pipe_through` applies to every route that follows it in the scope:

```elixir
pipeline :partners do
  plug SimpleTokenAuthentication, auth_realm: :partners
end

pipeline :acme_only do
  plug SimpleTokenAuthentication, auth_realm: :partners, services: [:acme]
end

scope "/", MyApp do
  pipe_through :partners
  get "/status", StatusController, :show            # acme or globex
end

scope "/acme", MyApp do
  pipe_through :acme_only
  post "/webhooks", AcmeWebhookController, :create  # acme only
end
```

For a single controller, put the plug in the controller instead and leave the route without an auth pipeline:

```elixir
defmodule MyApp.AcmeWebhookController do
  use MyApp, :controller

  plug SimpleTokenAuthentication, auth_realm: :partners, services: [:acme]
  # or only for some actions:
  # plug SimpleTokenAuthentication, [auth_realm: :partners, services: [:acme]] when action in [:create]
end
```

How it behaves:

- A `globex` token on an acme-only route is recognised but rejected with a `403` and the body `{ "error": "Service not allowed" }`. No `www-authenticate` header is sent, since the caller did authenticate.
- A token that matches nothing still gets the usual `401`.
- Omitting `services` keeps today's behaviour: any token in the realm is accepted.
- The list can name several services, e.g. `services: [:acme, :initech]`.
- With the default realm, `:global` names the top-level `token`, so `services: [:global]` admits only that token and `services: [:reporting]` admits only that service token.
- `services` must be a non-empty list of atoms; anything else raises when the plug is initialised. A name that is not configured in the realm is not an error, it just never matches.

## Hashed tokens

Tokens are stored in plaintext in config by default. Any token can instead be stored as its SHA-256 digest by writing it as a `{:sha256, hex}` tuple. This is opt-in per token: a plain string behaves exactly as before, and both forms can be mixed, including in one service's token list while rotating.

Generate the digest with `SimpleTokenAuthentication.hash_token/1`:

```sh
mix run -e 'IO.inspect(SimpleTokenAuthentication.hash_token("acme-secret"))'
# {:sha256, "307c609f87da43c3d563428a4f7efdf9857f4871fd10465732c4ab11a985a08c"}
```

Paste the tuple where the plaintext used to be:

```elixir
config :simple_token_authentication,
  token: {:sha256, "307c609f87da43c3d563428a4f7efdf9857f4871fd10465732c4ab11a985a08c"},
  service_tokens: [
    acme: {:sha256, "..."},
    globex: "still-plaintext"
  ]
```

Clients are unaffected and keep sending the plaintext token. The plug hashes the presented value and compares digests in constant time. Presenting the digest itself does not authenticate.

Rules and limits:

- The digest must be 64 hex characters, upper or lower case, and only `:sha256` is supported. Anything else raises an `ArgumentError` naming the service and realm when the realm is first used.
- This protects the token at rest in config files, config dumps and the running VM. It does not protect it in transit (use TLS), on the client, or against guessing.
- The hash is unsalted. Use long random tokens, for example `:crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)`. A short or guessable token is as weak hashed as it is in plaintext.

## Custom failure response

By default a request with no matching token gets a `401` with a JSON body and a `www-authenticate: Bearer realm="<realm>"` header, and a request whose service is not in `services` gets a `403` with a JSON body. Pass `on_failure` to send your own response in both cases. It receives the `Plug.Conn` and must send a response; the plug halts the conn afterwards.

```elixir
defmodule MyApp.AuthError do
  import Plug.Conn

  def unauthorized(conn) do
    conn
    |> put_resp_content_type("application/problem+json")
    |> send_resp(401, ~s({"title": "Unauthorized"}))
  end
end

plug SimpleTokenAuthentication, on_failure: {MyApp.AuthError, :unauthorized}
```

A 1-arity anonymous function is also accepted, but Phoenix routers evaluate plug options at compile time, so prefer the `{module, function}` form there.

The same handler is used for an unknown token and for a disallowed service. To tell them apart, check `conn.assigns[:simple_token_auth_service]`: it is set to the matched service name on the `403` path and absent on the `401` path.

```elixir
def unauthorized(%{assigns: %{simple_token_auth_service: service}} = conn) do
  send_resp(conn, 403, ~s({"title": "Forbidden", "service": "#{service}"}))
end

def unauthorized(conn) do
  send_resp(conn, 401, ~s({"title": "Unauthorized"}))
end
```

## Telemetry

Every request through the plug emits one of two events:

| Event | Measurements | Metadata |
|---|---|---|
| `[:simple_token_authentication, :auth, :success]` | `%{system_time: integer}` | `%{realm: atom, service: atom, conn: Plug.Conn.t()}` |
| `[:simple_token_authentication, :auth, :failure]` | `%{system_time: integer}` | `%{realm: atom, conn: Plug.Conn.t()}`, plus `service: atom` when rejected by `services` |

`realm` is `:default` when no `auth_realm` option is given. `service` is the matched service name, or `:global` for the top-level `token`. On a failure event, `service` is present only when the token matched but the service was not in the `services` list. The presented token is never included.

```elixir
:telemetry.attach("log-auth-failures", [:simple_token_authentication, :auth, :failure], fn _event, _measurements, %{realm: realm, conn: conn}, _ ->
  Logger.warning("auth failure in #{realm} from #{:inet.ntoa(conn.remote_ip)}")
end, nil)
```

## Configuration errors

Misconfiguration raises an `ArgumentError` with a message naming the realm and the expected shape. Checks fall into two groups by *when* they run.

Plug options are checked when the plug is initialised (at router compile time for a Phoenix router):

- `auth_realm` must be an atom
- `scheme` must be `:any`, `:bearer` or `:none`
- `on_failure`, when given, must be a 1-arity function or `{module, function}`
- `services`, when given, must be a non-empty list of atoms

Token configuration is read from the application environment, which is not available at init, so it is checked the first time a realm is used (on the first request to that realm):

- a realm named in `auth_realm` must be configured as a keyword list with a `service_tokens` key
- `service_tokens` must be a keyword list of service name to token
- every token must be a string, a `{:sha256, hex_digest}` tuple, or a list of those
- a hashed token must use `:sha256` and be a 64 hex character digest

If a realm ends up with no tokens at all, a warning is logged once and every request to that realm is rejected. Such a realm is retried on each request, so adding tokens later takes effect without a restart. A realm that already has tokens is cached; changing its tokens needs a restart.

## Notes

- A token value may be a single string or a list of strings (and a `{:sha256, hex}` tuple, see "Hashed tokens")
- Any token can be stored as a `{:sha256, hex}` digest instead of plaintext, see "Hashed tokens"
- Specifying `service_tokens` is optional
- Auth will succeed if token exists in *either* list (`token` or `service_tokens`)
- Use of a service token will add "service_name" to `Logging.metadata`
- Service can be identified in the conn.assigns[:simple_token_auth_service]. Will be the name of the service or :global when matching the token key
- Pass `services: [...]` to a plug call to accept only some of the realm's services on that route

## Copyright and License

Copyright (c) 2016 Podium
Copyright (c) 2026 Emmanuel Pinault

This work is free. You can redistribute it and/or modify it under the
terms of the MIT License. See the [LICENSE.md](./LICENSE.md) file for more details.
