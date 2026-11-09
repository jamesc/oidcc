# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.DeviceAuthorizationTest do
  use ExUnit.Case

  alias Oidcc.ClientContext
  alias Oidcc.DeviceAuthorization
  alias Oidcc.ProviderConfiguration
  alias Oidcc.Token

  doctest DeviceAuthorization

  {:ok, example_metadata} =
    :oidcc
    |> Application.app_dir("priv/test/fixtures/example-metadata.json")
    |> File.read!()
    |> JOSE.decode()
    |> Map.put("device_authorization_endpoint", "https://my.provider/device")
    |> ProviderConfiguration.decode_configuration()

  @example_metadata example_metadata
  @example_jwks :oidcc
                |> Application.app_dir("priv/test/fixtures/jwk.pem")
                |> JOSE.JWK.from_pem_file()

  setup do
    %{
      client_context:
        ClientContext.from_manual(@example_metadata, @example_jwks, "client_id", :unauthenticated)
    }
  end

  test "authorizes and polls until a token is issued", %{client_context: client_context} do
    adapter =
      {Oidcc.TestHttpAdapter,
       %{
         request: fn
           :post,
           {"https://my.provider/device", _headers, ~c"application/x-www-form-urlencoded",
            "client_id=client_id&scope=openid"} ->
             Oidcc.TestHttpAdapter.json_response(%{
               "device_code" => "device_code",
               "user_code" => "ABCD-EFGH",
               "verification_uri" => "https://my.provider/activate",
               "expires_in" => 900
             })

           :post,
           {"https://my.provider/token", _headers, ~c"application/x-www-form-urlencoded", body} ->
             assert %{
                      "grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
                      "device_code" => "device_code"
                    } = URI.decode_query(body)

             Oidcc.TestHttpAdapter.json_response(%{
               "access_token" => "access_token",
               "token_type" => "Bearer"
             })
         end
       }}

    opts = %{request_opts: %{http_adapter: adapter}}

    assert {:ok, %DeviceAuthorization{user_code: "ABCD-EFGH", interval: 5} = authorization} =
             DeviceAuthorization.authorize(client_context, Map.put(opts, :scope, ["openid"]))

    assert {:ok, %Token{access: %Token.Access{token: "access_token"}}} =
             Token.retrieve_device_token(authorization, client_context, opts)
  end

  test "reports a pending authorization", %{client_context: client_context} do
    adapter =
      {Oidcc.TestHttpAdapter,
       %{
         request: fn :post, {"https://my.provider/token", _headers, _content_type, _body} ->
           {:ok,
            {{~c"HTTP/1.1", 400, ~c"Bad Request"}, [{~c"content-type", ~c"application/json"}],
             JOSE.encode(%{"error" => "authorization_pending"})}}
         end
       }}

    assert {:error, :authorization_pending} =
             Token.retrieve_device_token("device_code", client_context, %{
               request_opts: %{http_adapter: adapter}
             })
  end
end
