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

    * `:on_failure` - how to respond when no token matches. Either a 1-arity
      function or a `{module, function}` tuple; it receives the `Plug.Conn` and
      must send a response. The plug halts the conn afterwards regardless.
      Defaults to a `401` JSON response with a `www-authenticate` header.

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
  require Logger

  @schemes [:any, :bearer, :none]

  def init(opts) do
    realm = Keyword.get(opts, :auth_realm)

    unless is_atom(realm) do
      raise ArgumentError, "invalid :auth_realm #{inspect(realm)}, expected an atom"
    end

    scheme = Keyword.get(opts, :scheme, :any)

    unless scheme in @schemes do
      raise ArgumentError,
            "invalid :scheme #{inspect(scheme)}, expected one of #{inspect(@schemes)}"
    end

    header = opts |> Keyword.get(:header, "authorization") |> String.downcase()

    case Keyword.get(opts, :on_failure) do
      nil ->
        :ok

      fun when is_function(fun, 1) ->
        :ok

      {mod, fun} when is_atom(mod) and is_atom(fun) ->
        :ok

      other ->
        raise ArgumentError,
              "invalid :on_failure #{inspect(other)}, expected a 1-arity function or {module, function}"
    end

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
        |> failure_response(Keyword.get(opts, :on_failure), store(realm))
        |> halt()
    end
  end

  defp failure_response(conn, nil, realm) do
    conn
    |> put_resp_header("www-authenticate", ~s(Bearer realm="#{realm}"))
    |> put_resp_content_type("application/json")
    |> send_resp(401, ~s({ "error": "Invalid shared key" }))
  end

  defp failure_response(conn, fun, _realm) when is_function(fun, 1), do: fun.(conn)
  defp failure_response(conn, {mod, fun}, _realm), do: apply(mod, fun, [conn])

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

    if token_map == %{} do
      Logger.warning(
        "SimpleTokenAuthentication: no tokens configured for realm #{inspect(store(realm))}, " <>
          "every request will be rejected"
      )
    end

    :persistent_term.put(store(realm), token_map)

    token_map
  end

  defp service_tokens(nil) do
    global = Application.get_env(:simple_token_authentication, :token)
    services = Application.get_env(:simple_token_authentication, :service_tokens)

    validate_tokens!(:token, global, :default)

    [{:global, global} | validate_service_tokens!(services, :default)]
  end

  defp service_tokens(realm) do
    case Application.get_env(:simple_token_authentication, realm) do
      nil ->
        raise ArgumentError,
              "SimpleTokenAuthentication realm #{inspect(realm)} is not configured, expected " <>
                "config :simple_token_authentication, #{inspect(realm)}, service_tokens: [...]"

      config when is_list(config) ->
        if Keyword.keyword?(config) do
          config |> Keyword.get(:service_tokens) |> validate_service_tokens!(realm)
        else
          raise_realm_shape!(realm, config)
        end

      config ->
        raise_realm_shape!(realm, config)
    end
  end

  defp raise_realm_shape!(realm, config) do
    raise ArgumentError,
          "SimpleTokenAuthentication realm #{inspect(realm)} must be a keyword list with a " <>
            ":service_tokens key, got: #{inspect(config)}"
  end

  defp validate_service_tokens!(nil, _realm), do: []

  defp validate_service_tokens!(services, realm) when is_list(services) do
    unless Keyword.keyword?(services) do
      raise ArgumentError,
            "SimpleTokenAuthentication :service_tokens for realm #{inspect(realm)} must be a " <>
              "keyword list of service name to token, got: #{inspect(services)}"
    end

    Enum.each(services, fn {service, tokens} -> validate_tokens!(service, tokens, realm) end)
    services
  end

  defp validate_service_tokens!(services, realm) do
    raise ArgumentError,
          "SimpleTokenAuthentication :service_tokens for realm #{inspect(realm)} must be a " <>
            "keyword list of service name to token, got: #{inspect(services)}"
  end

  defp validate_tokens!(_name, nil, _realm), do: :ok

  defp validate_tokens!(name, tokens, realm) do
    unless Enum.all?(List.wrap(tokens), &is_binary/1) do
      raise ArgumentError,
            "SimpleTokenAuthentication token for #{inspect(name)} in realm #{inspect(realm)} " <>
              "must be a string or list of strings, got: #{inspect(tokens)}"
    end

    :ok
  end

  defp store(nil) do
    :default
  end

  defp store(realm) do
    realm
  end
end
