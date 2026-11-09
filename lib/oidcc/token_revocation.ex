# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.TokenRevocation do
  use TelemetryRegistry

  telemetry_event(%{
    event: [:oidcc, :revoke_token, :start],
    description: "Emitted at the start of revoking the token",
    measurements: "%{system_time: non_neg_integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :revoke_token, :stop],
    description: "Emitted at the end of revoking the token",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :revoke_token, :exception],
    description: "Emitted at the end of revoking the token",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  @moduledoc """
  OAuth 2.0 Token Revocation

  See https://datatracker.ietf.org/doc/html/rfc7009

  ## Telemetry

  #{telemetry_docs()}
  """
  @moduledoc since: "3.10.0"

  alias Oidcc.ClientContext
  alias Oidcc.Token

  @doc """
  Revoke the given token

  For a full `Oidcc.Token` the refresh token is revoked when present,
  otherwise the access token. `:ok` is also returned when the token was
  already invalid (RFC 7009 §2.2).

  For a high level interface using `Oidcc.ProviderConfiguration.Worker`
  see `Oidcc.revoke_token/5`.

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://api.login.yahoo.com"
      ...>   })
      ...>
      ...> {:ok, client_context} =
      ...>   Oidcc.ClientContext.from_configuration_worker(
      ...>     pid,
      ...>     "client_id",
      ...>     "client_secret"
      ...>   )
      ...>
      ...> Oidcc.TokenRevocation.revoke(
      ...>   "access_token",
      ...>   client_context
      ...> )
      ...> # => :ok
  """
  @doc since: "3.10.0"
  @spec revoke(
          token :: String.t() | Token.t() | Token.Access.t() | Token.Refresh.t(),
          client_context :: ClientContext.t(),
          opts :: :oidcc_token_revocation.opts()
        ) :: :ok | {:error, :oidcc_token_revocation.error()}
  def revoke(token, client_context, opts \\ %{}) do
    client_context = ClientContext.struct_to_record(client_context)

    :oidcc_token_revocation.revoke(token_to_record(token), client_context, opts)
  end

  @doc false
  @spec token_to_record(token :: String.t() | Token.t() | Token.Access.t() | Token.Refresh.t()) ::
          binary() | :oidcc_token.t() | :oidcc_token.access() | :oidcc_token.refresh()
  def token_to_record(token) when is_binary(token), do: token
  def token_to_record(%Token{} = token), do: Token.struct_to_record(token)
  def token_to_record(%Token.Access{} = token), do: Token.Access.struct_to_record(token)
  def token_to_record(%Token.Refresh{} = token), do: Token.Refresh.struct_to_record(token)
end
