defmodule SimpleTokenAuthentication.OnFailureTest do
  use ExUnit.Case, async: false
  import Plug.Test
  import Plug.Conn

  setup do
    :persistent_term.erase(:default)
    :persistent_term.erase(:another_realm)
    Application.put_env(:simple_token_authentication, :token, "secret")

    Application.put_env(:simple_token_authentication, :another_realm,
      service_tokens: [acme: "acme"]
    )

    on_exit(fn ->
      Application.put_env(:simple_token_authentication, :token, nil)
      Application.put_env(:simple_token_authentication, :another_realm, nil)
    end)

    :ok
  end

  defp call(value, opts \\ []) do
    conn = put_req_header(conn(:get, "/foo"), "authorization", value)
    SimpleTokenAuthentication.call(conn, SimpleTokenAuthentication.init(opts))
  end

  def forbidden(conn) do
    conn |> put_resp_content_type("text/plain") |> send_resp(403, "nope")
  end

  def forgets_to_halt(conn) do
    send_resp(conn, 418, "teapot")
  end

  describe "default failure response" do
    test "returns 401 with the JSON body" do
      conn = call("wrong")
      assert conn.status == 401
      assert conn.resp_body == ~s({ "error": "Invalid shared key" })
      assert conn.halted
    end

    test "adds a WWW-Authenticate header naming the realm" do
      assert get_resp_header(call("wrong"), "www-authenticate") == [~s(Bearer realm="default")]

      assert get_resp_header(call("wrong", auth_realm: :another_realm), "www-authenticate") ==
               [~s(Bearer realm="another_realm")]
    end
  end

  describe "on_failure with {module, function}" do
    test "uses the handler's response" do
      conn = call("wrong", on_failure: {__MODULE__, :forbidden})
      assert conn.status == 403
      assert conn.resp_body == "nope"
      assert get_resp_header(conn, "content-type") == ["text/plain; charset=utf-8"]
    end

    test "halts even if the handler does not" do
      conn = call("wrong", on_failure: {__MODULE__, :forgets_to_halt})
      assert conn.status == 418
      assert conn.halted
    end

    test "is not invoked on success" do
      conn = call("secret", on_failure: {__MODULE__, :forbidden})
      assert conn.status == nil
      refute conn.halted
    end
  end

  describe "on_failure with an anonymous function" do
    test "uses the handler's response" do
      conn = call("wrong", on_failure: fn conn -> send_resp(conn, 404, "gone") end)
      assert conn.status == 404
      assert conn.resp_body == "gone"
      assert conn.halted
    end
  end

  describe "init/1" do
    test "rejects a handler that is not a function or {module, function}" do
      assert_raise ArgumentError, fn -> SimpleTokenAuthentication.init(on_failure: "nope") end

      assert_raise ArgumentError, fn ->
        SimpleTokenAuthentication.init(on_failure: fn -> :ok end)
      end

      assert_raise ArgumentError, fn ->
        SimpleTokenAuthentication.init(on_failure: {Foo, "bar"})
      end
    end
  end
end
