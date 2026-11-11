defmodule SimpleTokenAuthentication.HashedTokensTest do
  use ExUnit.Case, async: false
  import Plug.Test
  import Plug.Conn

  # SHA-256 of "acme-secret"
  @acme_digest "c0d0ff2f3cf8bf9d0a6b0d8e4e3bb7e5a5f6b8ed3b1c5f0c5f5d4b2a1e9c8d7f"

  setup do
    :persistent_term.erase(:default)
    :persistent_term.erase(:partners)
    Application.put_env(:simple_token_authentication, :token, nil)
    Application.put_env(:simple_token_authentication, :service_tokens, nil)
    Application.put_env(:simple_token_authentication, :partners, nil)

    on_exit(fn ->
      Application.put_env(:simple_token_authentication, :token, nil)
      Application.put_env(:simple_token_authentication, :service_tokens, nil)
      Application.put_env(:simple_token_authentication, :partners, nil)
    end)

    :ok
  end

  defp call(value, opts \\ []) do
    conn = put_req_header(conn(:get, "/foo"), "authorization", value)
    SimpleTokenAuthentication.call(conn, SimpleTokenAuthentication.init(opts))
  end

  defp sha256_hex(value), do: Base.encode16(:crypto.hash(:sha256, value), case: :lower)

  describe "hash_token/1" do
    test "returns a paste-ready {:sha256, hex} tuple" do
      assert {:sha256, hex} = SimpleTokenAuthentication.hash_token("acme-secret")
      assert hex == sha256_hex("acme-secret")
      assert String.length(hex) == 64
      assert hex == String.downcase(hex)
    end
  end

  describe "hashed service token" do
    setup do
      Application.put_env(:simple_token_authentication, :service_tokens,
        acme: SimpleTokenAuthentication.hash_token("acme-secret"),
        globex: "globex-plain"
      )

      :ok
    end

    test "authenticates the plaintext value" do
      conn = call("acme-secret")
      refute conn.halted
      assert conn.assigns[:simple_token_auth_service] == :acme
    end

    test "does not accept the digest itself as a token" do
      {:sha256, hex} = SimpleTokenAuthentication.hash_token("acme-secret")
      assert call(hex).status == 401
    end

    test "rejects a wrong value" do
      assert call("acme-secre").status == 401
      assert call("").status == 401
    end

    test "plaintext tokens in the same list keep working" do
      conn = call("globex-plain")
      refute conn.halted
      assert conn.assigns[:simple_token_auth_service] == :globex
    end

    test "works with the Bearer scheme" do
      refute call("Bearer acme-secret", scheme: :bearer).halted
    end
  end

  describe "hashed top-level token" do
    test "authenticates as :global" do
      Application.put_env(
        :simple_token_authentication,
        :token,
        SimpleTokenAuthentication.hash_token("admin-secret")
      )

      conn = call("admin-secret")
      refute conn.halted
      assert conn.assigns[:simple_token_auth_service] == :global
    end

    test "can be mixed with plaintext in a list for rotation" do
      Application.put_env(:simple_token_authentication, :token, [
        "old-plain",
        SimpleTokenAuthentication.hash_token("new-secret")
      ])

      refute call("old-plain").halted
      refute call("new-secret").halted
      assert call("other").status == 401
    end
  end

  describe "hashed token in a named realm" do
    test "authenticates within the realm only" do
      Application.put_env(:simple_token_authentication, :partners,
        service_tokens: [acme: SimpleTokenAuthentication.hash_token("acme-secret")]
      )

      Application.put_env(:simple_token_authentication, :token, "admin")

      refute call("acme-secret", auth_realm: :partners).halted
      assert call("acme-secret").status == 401
      assert call("admin", auth_realm: :partners).status == 401
    end
  end

  describe "digest format" do
    test "accepts an upper-case hex digest" do
      Application.put_env(:simple_token_authentication, :service_tokens,
        acme: {:sha256, String.upcase(sha256_hex("acme-secret"))}
      )

      refute call("acme-secret").halted
    end

    test "rejects a digest that is not 64 hex characters" do
      Application.put_env(:simple_token_authentication, :service_tokens,
        acme: {:sha256, "not-a-digest"}
      )

      assert_raise ArgumentError, ~r/:acme.*64 hex/s, fn -> call("anything") end
    end

    test "rejects an unknown hash algorithm" do
      Application.put_env(:simple_token_authentication, :service_tokens,
        acme: {:md5, @acme_digest}
      )

      assert_raise ArgumentError, ~r/:acme.*only :sha256/s, fn -> call("anything") end
    end

    test "rejects a digest tuple on the top-level token with a clear message" do
      Application.put_env(:simple_token_authentication, :token, {:sha256, 123})

      assert_raise ArgumentError, ~r/:token.*64 hex/s, fn -> call("anything") end
    end
  end

  describe "hashed token combined with the services allow list" do
    setup do
      Application.put_env(:simple_token_authentication, :partners,
        service_tokens: [
          acme: SimpleTokenAuthentication.hash_token("acme-secret"),
          globex: "globex-plain"
        ]
      )

      :ok
    end

    test "an allowed service authenticates with its hashed token" do
      conn = call("acme-secret", auth_realm: :partners, services: [:acme])
      refute conn.halted
      assert conn.assigns[:simple_token_auth_service] == :acme
    end

    test "a disallowed service is still rejected with a 403 even when its token is valid" do
      conn = call("globex-plain", auth_realm: :partners, services: [:acme])
      assert conn.status == 403
      assert conn.assigns[:simple_token_auth_service] == :globex
    end

    test "an unknown token is a 401, not a 403" do
      assert call("nope", auth_realm: :partners, services: [:acme]).status == 401
    end
  end
end
