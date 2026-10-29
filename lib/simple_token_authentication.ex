defmodule SimpleTokenAuthentication do
  @moduledoc """
  A plug that checks for presence of a simple token for authentication.

  ## Options

    * `:auth_realm` - the configured realm to look tokens up in. Defaults to the
      top-level `:token` and `:service_tokens` configuration.
    * `:header` - the request header the token is read from. Defaults to
      `"authorization"`.
    * `:scheme` - how the header value is interpreted:
      * `:any` (default) - accepts either a bare token or `Bearer <token>`
      * `:bearer` - requires `Bearer <token>`
      * `:none` - requires a bare token

  The `Bearer` scheme name is matched case-insensitively.

  ## Telemetry

  The following events are emitted on every request through the plug:

    * `[:simple_token_authentication, :auth, :success]` - measurements
      `%{system_time: integer}`, metadata `%{realm: atom, service: atom, conn: Plug.Conn.t()}`
    * `[:simple_token_authentication, :auth, :failure]` - measurements
      `%{system_time: integer}`, metadata `%{realm: atom, conn: Plug.Conn.t()}`

  `:realm` is `:default` when no `:auth_realm` option is given. `:service` is
  the matched service name, or `:global` for the top-level `:token`. The
  presented token is never included in metadata.
  """
  @behaviour Plug

  import Plug.Conn

  @schemes [:any, :bearer, :none]

  def init(opts) do
    scheme = Keyword.get(opts, :scheme, :any)

    unless scheme in @schemes do
      raise ArgumentError,
            "invalid :scheme #{inspect(scheme)}, expected one of #{inspect(@schemes)}"
    end

    header = opts |> Keyword.get(:header, "authorization") |> String.downcase()

    opts
    |> Keyword.put(:scheme, scheme)
    |> Keyword.put(:header, header)
  end

  def call(conn, opts) do
    realm = Keyword.get(opts, :auth_realm)

    val =
      conn |> get_auth_header(Keyword.get(opts, :header, "authorization")) |> extract_token(opts)

    token_map =
      case :persistent_term.get(store(realm), nil) do
        nil ->
          build_token_map(realm)

        val ->
          val
      end

    case secure_lookup(token_map, val) do
      {:ok, service_name} ->
        emit(:success, %{realm: store(realm), service: service_name, conn: conn})
        Logger.metadata(service_name: service_name)
        assign(conn, :simple_token_auth_service, service_name)

      :error ->
        emit(:failure, %{realm: store(realm), conn: conn})

        conn
        |> put_resp_content_type("application/json")
        |> send_resp(401, ~s({ "error": "Invalid shared key" }))
        |> halt()
    end
  end

  defp emit(event, metadata) do
    :telemetry.execute(
      [:simple_token_authentication, :auth, event],
      %{system_time: System.system_time()},
      metadata
    )
  end

  defp secure_lookup(token_map, val) do
    Enum.find_value(token_map, :error, fn {token, service_name} ->
      if Plug.Crypto.secure_compare(token, val), do: {:ok, service_name}
    end)
  end

  defp get_auth_header(conn, header) do
    case get_req_header(conn, header) do
      [val | _] -> val
      _ -> ""
    end
  end

  defp extract_token(val, opts) do
    case {Keyword.get(opts, :scheme, :any), String.split(val, " ", parts: 2)} do
      {scheme, [prefix, token]} when scheme in [:any, :bearer] ->
        if String.downcase(prefix) == "bearer", do: token, else: ""

      {:any, [token]} ->
        token

      {:none, [token]} ->
        token

      _ ->
        ""
    end
  end

  defp build_token_map(nil) do
    global = token()
    services = service_tokens(nil)

    token_map =
      for {service, tokens} <- [{:global, global} | services],
          token <- List.wrap(tokens),
          token != "",
          reduce: %{} do
        acc ->
          Map.put(acc, token, service)
      end

    :persistent_term.put(store(nil), token_map)

    token_map
  end

  defp build_token_map(realm) do
    services = service_tokens(realm)

    token_map =
      for {service, tokens} <- services,
          token <- List.wrap(tokens),
          token != "",
          reduce: %{} do
        acc ->
          Map.put(acc, token, service)
      end

    :persistent_term.put(store(realm), token_map)

    token_map
  end

  defp service_tokens(nil) do
    :simple_token_authentication
    |> Application.get_env(:service_tokens)
    |> List.wrap()
  end

  defp service_tokens(realm) do
    :simple_token_authentication
    |> Application.get_env(realm)
    |> Keyword.get(:service_tokens)
    |> List.wrap()
  end

  defp token do
    :simple_token_authentication
    |> Application.get_env(:token)
    |> List.wrap()
  end

  defp store(nil) do
    :default
  end

  defp store(realm) do
    realm
  end
end
