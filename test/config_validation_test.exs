defmodule SimpleTokenAuthentication.ConfigValidationTest do
  use ExUnit.Case, async: false
  import Plug.Test
  import Plug.Conn
  import ExUnit.CaptureLog

  setup do
    :persistent_term.erase(:default)
    :persistent_term.erase(:missing_realm)
    :persistent_term.erase(:bad_realm)
    Application.put_env(:simple_token_authentication, :token, nil)
    Application.put_env(:simple_token_authentication, :service_tokens, nil)

    on_exit(fn ->
      Application.delete_env(:simple_token_authentication, :missing_realm)
      Application.delete_env(:simple_token_authentication, :bad_realm)
      Application.put_env(:simple_token_authentication, :token, nil)
      Application.put_env(:simple_token_authentication, :service_tokens, nil)
    end)

    :ok
  end

  defp call(opts) do
    conn = put_req_header(conn(:get, "/foo"), "authorization", "anything")
    SimpleTokenAuthentication.call(conn, SimpleTokenAuthentication.init(opts))
  end

  describe "init/1" do
    test "rejects a non-atom auth_realm" do
      assert_raise ArgumentError, ~r/auth_realm/, fn ->
        SimpleTokenAuthentication.init(auth_realm: "realm")
      end
    end
  end

  describe "unconfigured realm" do
    test "raises a clear error naming the realm and expected key" do
      assert_raise ArgumentError, ~r/:missing_realm.*service_tokens/s, fn ->
        call(auth_realm: :missing_realm)
      end
    end
  end

  describe "malformed realm config" do
    test "raises when the realm config is not a keyword list" do
      Application.put_env(:simple_token_authentication, :bad_realm, "tokens")

      assert_raise ArgumentError, ~r/:bad_realm/, fn -> call(auth_realm: :bad_realm) end
    end

    test "raises when service_tokens is not a keyword list" do
      Application.put_env(:simple_token_authentication, :bad_realm, service_tokens: %{"a" => "b"})

      assert_raise ArgumentError, ~r/service_tokens/, fn -> call(auth_realm: :bad_realm) end
    end

    test "raises when the realm config is a list but not a keyword list" do
      Application.put_env(:simple_token_authentication, :bad_realm, ["a", "b"])

      assert_raise ArgumentError, ~r/:bad_realm.*keyword list/s, fn ->
        call(auth_realm: :bad_realm)
      end
    end

    test "raises when the default realm service_tokens is a list but not a keyword list" do
      Application.put_env(:simple_token_authentication, :service_tokens, ["a", "b"])

      assert_raise ArgumentError, ~r/service_tokens.*:default/s, fn -> call([]) end
    end

    test "raises when a service token is not a string" do
      Application.put_env(:simple_token_authentication, :service_tokens, acme: 123)

      assert_raise ArgumentError, ~r/acme/, fn -> call([]) end
    end

    test "raises when the global token is not a string" do
      Application.put_env(:simple_token_authentication, :token, :nope)

      assert_raise ArgumentError, ~r/:token/, fn -> call([]) end
    end
  end

  describe "empty token set" do
    test "logs a warning for the default realm and rejects the request" do
      {conn, log} = with_log(fn -> call([]) end)
      assert conn.status == 401
      assert log =~ "no tokens configured"
      assert log =~ "default"
    end

    test "logs a warning for a realm without service_tokens" do
      Application.put_env(:simple_token_authentication, :bad_realm, [])

      {conn, log} = with_log(fn -> call(auth_realm: :bad_realm) end)
      assert conn.status == 401
      assert log =~ "no tokens configured"
      assert log =~ "bad_realm"
    end

    test "warns only once per realm" do
      {_, log} =
        with_log(fn ->
          call([])
          call([])
        end)

      assert length(String.split(log, "no tokens configured")) == 2
    end
  end

  describe "recovering from an empty realm" do
    test "picks up tokens configured after the first request, without a manual erase" do
      do_call = fn value ->
        req = put_req_header(conn(:get, "/foo"), "authorization", value)
        SimpleTokenAuthentication.call(req, SimpleTokenAuthentication.init([]))
      end

      # realm starts empty
      assert do_call.("late-token").status == 401

      # tokens appear later (e.g. runtime config); no restart, no persistent_term.erase
      Application.put_env(:simple_token_authentication, :token, "late-token")

      refute do_call.("late-token").halted
    end
  end

  describe "caching a populated realm" do
    test "builds the token map once and does not pick up a changed token without a restart" do
      do_call = fn value ->
        req = put_req_header(conn(:get, "/foo"), "authorization", value)
        SimpleTokenAuthentication.call(req, SimpleTokenAuthentication.init([]))
      end

      Application.put_env(:simple_token_authentication, :token, "first")
      refute do_call.("first").halted

      # change the token after the realm is cached; no persistent_term.erase
      Application.put_env(:simple_token_authentication, :token, "second")

      # the cached map still holds the original token
      refute do_call.("first").halted
      assert do_call.("second").status == 401
    end
  end
end
