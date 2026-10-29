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
  [{:simple_token_authentication, "~> 1.0"}]
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

## Custom failure response

By default a request with no matching token gets a `401` with a JSON body and a `www-authenticate: Bearer realm="<realm>"` header. Pass `on_failure` to send your own response. It receives the `Plug.Conn` and must send a response; the plug halts the conn afterwards.

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

## Telemetry

Every request through the plug emits one of two events:

| Event | Measurements | Metadata |
|---|---|---|
| `[:simple_token_authentication, :auth, :success]` | `%{system_time: integer}` | `%{realm: atom, service: atom, conn: Plug.Conn.t()}` |
| `[:simple_token_authentication, :auth, :failure]` | `%{system_time: integer}` | `%{realm: atom, conn: Plug.Conn.t()}` |

`realm` is `:default` when no `auth_realm` option is given. `service` is the matched service name, or `:global` for the top-level `token`. The presented token is never included.

```elixir
:telemetry.attach("log-auth-failures", [:simple_token_authentication, :auth, :failure], fn _event, _measurements, %{realm: realm, conn: conn}, _ ->
  Logger.warning("auth failure in #{realm} from #{:inet.ntoa(conn.remote_ip)}")
end, nil)
```

## Configuration errors

Misconfiguration raises an `ArgumentError` with a message naming the realm and the expected shape, rather than failing obscurely on the first request:

- `auth_realm` must be an atom (checked when the plug is initialised)
- a realm named in `auth_realm` must be configured as a keyword list with a `service_tokens` key
- `service_tokens` must be a keyword list of service name to token
- every token must be a string or a list of strings

If a realm ends up with no tokens at all, a warning is logged once and every request to that realm is rejected.

## Notes

- Token value can be a comma-separated list of tokens
- Specifying `service_tokens` is optional
- Auth will succeed if token exists in *either* list (`token` or `service_tokens`)
- Use of a service token will add "service_name" to `Logging.metadata`
- Service can be identified in the conn.assigns[:simple_token_auth_service]. Will be the name of the service or :global when matching the token key

## Copyright and License

Copyright (c) 2016 Podium
Copyright (c) 2026 Emmanuel Pinault

This work is free. You can redistribute it and/or modify it under the
terms of the MIT License. See the [LICENSE.md](./LICENSE.md) file for more details.
