defmodule SimpleTokenAuthentication.TelemetryTest do
  use ExUnit.Case, async: false
  import Plug.Test
  import Plug.Conn

  @success [:simple_token_authentication, :auth, :success]
  @failure [:simple_token_authentication, :auth, :failure]

  setup do
    :persistent_term.erase(:default)
    :persistent_term.erase(:another_realm)
    Application.put_env(:simple_token_authentication, :token, "secret")
    Application.put_env(:simple_token_authentication, :service_tokens, billing: "bill")

    Application.put_env(:simple_token_authentication, :another_realm,
      service_tokens: [acme: "acme"]
    )

    on_exit(fn ->
      Application.put_env(:simple_token_authentication, :token, nil)
      Application.put_env(:simple_token_authentication, :service_tokens, nil)
      Application.put_env(:simple_token_authentication, :another_realm, nil)
    end)

    test_pid = self()
    handler_id = {__MODULE__, make_ref()}

    :telemetry.attach_many(
      handler_id,
      [@success, @failure],
      &__MODULE__.handle_event/4,
      test_pid
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)
    :ok
  end

  def handle_event(event, measurements, metadata, test_pid) do
    send(test_pid, {event, measurements, metadata})
  end

  defp call(value, opts \\ []) do
    conn = put_req_header(conn(:get, "/foo"), "authorization", value)
    SimpleTokenAuthentication.call(conn, SimpleTokenAuthentication.init(opts))
  end

  test "emits a success event with realm and service for a service token" do
    call("bill")

    assert_received {@success, %{system_time: time},
                     %{realm: :default, service: :billing, conn: %Plug.Conn{}}}

    assert is_integer(time)
  end

  test "emits a success event with service :global for the global token" do
    call("secret")
    assert_received {@success, _, %{realm: :default, service: :global}}
  end

  test "uses the realm name in the success event" do
    call("acme", auth_realm: :another_realm)
    assert_received {@success, _, %{realm: :another_realm, service: :acme}}
  end

  test "emits a failure event with the realm on a bad token" do
    call("wrong")
    assert_received {@failure, %{system_time: _}, %{realm: :default, conn: %Plug.Conn{}} = meta}
    refute Map.has_key?(meta, :service)
    refute_received {@success, _, _}
  end

  test "emits a failure event with the realm name for a realm" do
    call("wrong", auth_realm: :another_realm)
    assert_received {@failure, _, %{realm: :another_realm}}
  end

  test "failure metadata never carries the presented token" do
    call("wrong")
    assert_received {@failure, measurements, metadata}
    refute "wrong" in Map.values(metadata)
    refute "wrong" in Map.values(measurements)
  end
end
