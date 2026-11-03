defmodule SimpleTokenAuthentication.ServicesTest do
  use ExUnit.Case, async: false
  import Plug.Test
  import Plug.Conn

  @failure [:simple_token_authentication, :auth, :failure]

  setup do
    :persistent_term.erase(:default)
    :persistent_term.erase(:partners)
    Application.put_env(:simple_token_authentication, :token, "admin")
    Application.put_env(:simple_token_authentication, :service_tokens, reporting: "report")

    Application.put_env(:simple_token_authentication, :partners,
      service_tokens: [acme: "acme-token", globex: "globex-token", initech: "initech-token"]
    )

    on_exit(fn ->
      Application.put_env(:simple_token_authentication, :token, nil)
      Application.put_env(:simple_token_authentication, :service_tokens, nil)
      Application.put_env(:simple_token_authentication, :partners, nil)
    end)

    :ok
  end

  defp call(value, opts) do
    conn = put_req_header(conn(:get, "/foo"), "authorization", value)
    SimpleTokenAuthentication.call(conn, SimpleTokenAuthentication.init(opts))
  end

  def forbidden_handler(conn) do
    service = conn.assigns[:simple_token_auth_service]
    send_resp(conn, 403, "no entry for #{service}")
  end

  describe "services allow list within a realm" do
    test "lets an allowed service through" do
      conn = call("acme-token", auth_realm: :partners, services: [:acme])
      refute conn.halted
      assert conn.status == nil
      assert conn.assigns[:simple_token_auth_service] == :acme
    end

    test "rejects another service from the same realm with a 403" do
      conn = call("globex-token", auth_realm: :partners, services: [:acme])
      assert conn.halted
      assert conn.status == 403
      assert conn.resp_body == ~s({ "error": "Service not allowed" })
      assert get_resp_header(conn, "content-type") == ["application/json; charset=utf-8"]
    end

    test "does not send www-authenticate on a 403, the caller is authenticated" do
      conn = call("globex-token", auth_realm: :partners, services: [:acme])
      assert get_resp_header(conn, "www-authenticate") == []
    end

    test "accepts any service named in the list" do
      assert call("acme-token", auth_realm: :partners, services: [:acme, :initech]).status == nil

      assert call("initech-token", auth_realm: :partners, services: [:acme, :initech]).status ==
               nil

      assert call("globex-token", auth_realm: :partners, services: [:acme, :initech]).status ==
               403
    end

    test "still returns 401 for a token that matches nothing" do
      conn = call("nope", auth_realm: :partners, services: [:acme])
      assert conn.status == 401
      assert get_resp_header(conn, "www-authenticate") == [~s(Bearer realm="partners")]
    end

    test "omitting services keeps every service in the realm allowed" do
      assert call("acme-token", auth_realm: :partners).status == nil
      assert call("globex-token", auth_realm: :partners).status == nil
    end
  end

  describe "services with the default realm" do
    test ":global names the top-level token" do
      assert call("admin", services: [:global]).status == nil
      assert call("report", services: [:global]).status == 403
    end

    test "a service token can be allowed on its own" do
      assert call("report", services: [:reporting]).status == nil
      assert call("admin", services: [:reporting]).status == 403
    end
  end

  describe "interaction with on_failure" do
    test "a disallowed service goes through the custom handler" do
      conn =
        call("globex-token",
          auth_realm: :partners,
          services: [:acme],
          on_failure: {__MODULE__, :forbidden_handler}
        )

      assert conn.halted
      assert conn.status == 403
      assert conn.resp_body == "no entry for globex"
    end

    test "the service assign is set so the handler can tell 401 from 403" do
      conn =
        call("globex-token",
          auth_realm: :partners,
          services: [:acme],
          on_failure: fn conn -> send_resp(conn, 403, "") end
        )

      assert conn.assigns[:simple_token_auth_service] == :globex

      conn =
        call("nope",
          auth_realm: :partners,
          services: [:acme],
          on_failure: fn conn -> send_resp(conn, 401, "") end
        )

      refute Map.has_key?(conn.assigns, :simple_token_auth_service)
    end
  end

  describe "telemetry" do
    setup do
      test_pid = self()
      handler_id = {__MODULE__, make_ref()}

      :telemetry.attach(handler_id, @failure, &__MODULE__.handle_event/4, test_pid)
      on_exit(fn -> :telemetry.detach(handler_id) end)
      :ok
    end

    def handle_event(event, measurements, metadata, test_pid) do
      send(test_pid, {event, measurements, metadata})
    end

    test "a disallowed service emits a failure event naming the service" do
      call("globex-token", auth_realm: :partners, services: [:acme])

      assert_receive {@failure, _measurements, %{realm: :partners, service: :globex, conn: _}}
    end

    test "an unknown token emits a failure event without a service" do
      call("nope", auth_realm: :partners, services: [:acme])

      assert_receive {@failure, _measurements, %{realm: :partners} = metadata}
      refute Map.has_key?(metadata, :service)
    end
  end

  describe "init/1" do
    test "accepts a non-empty list of atoms" do
      opts = SimpleTokenAuthentication.init(services: [:acme, :global])
      assert Keyword.get(opts, :services) == [:acme, :global]
    end

    test "rejects a value that is not a list" do
      assert_raise ArgumentError, ~r/:services/, fn ->
        SimpleTokenAuthentication.init(services: :acme)
      end
    end

    test "rejects an empty list" do
      assert_raise ArgumentError, ~r/:services/, fn ->
        SimpleTokenAuthentication.init(services: [])
      end
    end

    test "rejects entries that are not atoms" do
      assert_raise ArgumentError, ~r/:services/, fn ->
        SimpleTokenAuthentication.init(services: ["acme"])
      end
    end
  end
end
