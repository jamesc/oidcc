# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.TokenRevocationTest do
  use ExUnit.Case

  alias Oidcc.ClientContext
  alias Oidcc.ProviderConfiguration
  alias Oidcc.Token
  alias Oidcc.TokenRevocation

  doctest TokenRevocation

  {:ok, example_metadata} =
    :oidcc
    |> Application.app_dir("priv/test/fixtures/example-metadata.json")
    |> File.read!()
    |> JOSE.decode()
    |> ProviderConfiguration.decode_configuration()

  @example_metadata example_metadata
  @example_jwks :oidcc
                |> Application.app_dir("priv/test/fixtures/jwk.pem")
                |> JOSE.JWK.from_pem_file()

  describe inspect(&TokenRevocation.revoke/3) do
    test "revokes the refresh token of a full token" do
      adapter =
        {Oidcc.TestHttpAdapter,
         %{
           request: fn
             :post,
             {"https://my.provider/revoke", _headers, ~c"application/x-www-form-urlencoded",
              "token=refresh_token&token_type_hint=refresh_token"} ->
               {:ok, {{~c"HTTP/1.1", 200, ~c"OK"}, [], ""}}
           end
         }}

      client_context =
        ClientContext.from_manual(
          @example_metadata,
          @example_jwks,
          "client_id",
          "client_secret"
        )

      assert :ok =
               TokenRevocation.revoke(
                 %Token{
                   id: :none,
                   access: %Token.Access{token: "access_token", expires: :undefined},
                   refresh: %Token.Refresh{token: "refresh_token"},
                   scope: ["profile", "openid"]
                 },
                 client_context,
                 %{request_opts: %{http_adapter: adapter}}
               )
    end

    test "revokes a raw token" do
      adapter =
        {Oidcc.TestHttpAdapter,
         %{
           request: fn
             :post,
             {"https://my.provider/revoke", _headers, ~c"application/x-www-form-urlencoded",
              "token=access_token"} ->
               {:ok, {{~c"HTTP/1.1", 200, ~c"OK"}, [], ""}}
           end
         }}

      client_context =
        ClientContext.from_manual(
          @example_metadata,
          @example_jwks,
          "client_id",
          "client_secret"
        )

      assert :ok =
               TokenRevocation.revoke("access_token", client_context, %{
                 request_opts: %{http_adapter: adapter}
               })
    end
  end
end
