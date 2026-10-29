defmodule SimpleTokenAuthentication.SchemeAndHeaderTest do
  use ExUnit.Case, async: false
  import Plug.Test
  import Plug.Conn

  setup do
    :persistent_term.erase(:default)
    Application.put_env(:simple_token_authentication, :token, "secret")
    on_exit(fn -> Application.put_env(:simple_token_authentication, :token, nil) end)
    :ok
  end

  defp call(header_name, value, opts) do
    conn = put_req_header(conn(:get, "/foo"), header_name, value)
    SimpleTokenAuthentication.call(conn, SimpleTokenAuthentication.init(opts))
  end

  describe "default scheme (:any)" do
    test "accepts a bare token" do
      assert call("authorization", "secret", []).status != 401
    end

    test "accepts a Bearer-prefixed token" do
      assert call("authorization", "Bearer secret", []).status != 401
    end

    test "matches the Bearer scheme case-insensitively" do
      assert call("authorization", "bEaReR secret", []).status != 401
    end

    test "rejects an unknown scheme" do
      assert call("authorization", "Basic secret", []).status == 401
    end
  end

  describe "scheme: :bearer" do
    test "accepts a Bearer-prefixed token" do
      assert call("authorization", "Bearer secret", scheme: :bearer).status != 401
    end

    test "rejects a bare token" do
      assert call("authorization", "secret", scheme: :bearer).status == 401
    end
  end

  describe "scheme: :none" do
    test "accepts a bare token" do
      assert call("authorization", "secret", scheme: :none).status != 401
    end

    test "rejects a Bearer-prefixed token" do
      assert call("authorization", "Bearer secret", scheme: :none).status == 401
    end
  end

  describe "header option" do
    test "reads the token from the configured header" do
      assert call("x-api-key", "secret", header: "x-api-key").status != 401
    end

    test "ignores the authorization header when another header is configured" do
      assert call("authorization", "secret", header: "x-api-key").status == 401
    end

    test "normalises the header name to lowercase" do
      assert call("x-api-key", "secret", header: "X-Api-Key").status != 401
    end
  end

  describe "init/1" do
    test "rejects an unknown scheme" do
      assert_raise ArgumentError, fn -> SimpleTokenAuthentication.init(scheme: :basic) end
    end
  end
end
