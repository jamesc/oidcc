# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.DeviceAuthorization do
  use TelemetryRegistry

  telemetry_event(%{
    event: [:oidcc, :device_authorization, :start],
    description: "Emitted at the start of requesting a device authorization",
    measurements: "%{system_time: non_neg_integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :device_authorization, :stop],
    description: "Emitted at the end of requesting a device authorization",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  telemetry_event(%{
    event: [:oidcc, :device_authorization, :exception],
    description: "Emitted at the end of requesting a device authorization",
    measurements: "%{duration: integer(), monotonic_time: integer()}",
    metadata: "%{issuer: :uri_string.uri_string(), client_id: String.t()}"
  })

  @moduledoc """
  OAuth 2.0 Device Authorization Grant

  See https://datatracker.ietf.org/doc/html/rfc8628

  `authorize/2` starts the flow. Show the user `user_code` and
  `verification_uri` (or `verification_uri_complete`), then poll
  `Oidcc.Token.retrieve_device_token/3` every `interval` seconds.

  ## Telemetry

  #{telemetry_docs()}
  """
  @moduledoc since: "3.10.0"

  use Oidcc.RecordStruct,
    internal_name: :device_authorization,
    record_name: :oidcc_device_authorization,
    hrl: "include/oidcc_device_authorization.hrl"

  alias Oidcc.ClientContext

  @typedoc """
  For details on the fields see:
  * https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
  """
  @typedoc since: "3.10.0"
  @type t() :: %__MODULE__{
          device_code: String.t(),
          user_code: String.t(),
          verification_uri: :uri_string.uri_string(),
          verification_uri_complete: :uri_string.uri_string() | :undefined,
          expires_in: pos_integer(),
          interval: pos_integer(),
          extra: %{String.t() => term()}
        }

  @doc """
  Start a device authorization

  For a high level interface using `Oidcc.ProviderConfiguration.Worker`
  see `Oidcc.device_authorization/4`.

  ## Examples

      iex> {:ok, pid} =
      ...>   Oidcc.ProviderConfiguration.Worker.start_link(%{
      ...>     issuer: "https://accounts.google.com"
      ...>   })
      ...>
      ...> {:ok, client_context} =
      ...>   Oidcc.ClientContext.from_configuration_worker(
      ...>     pid,
      ...>     "client_id",
      ...>     :unauthenticated
      ...>   )
      ...>
      ...> Oidcc.DeviceAuthorization.authorize(
      ...>   client_context,
      ...>   %{scope: ["openid"]}
      ...> )
      ...> # => {:ok, %Oidcc.DeviceAuthorization{}}
  """
  @doc since: "3.10.0"
  @spec authorize(
          client_context :: ClientContext.t(),
          opts :: :oidcc_device_authorization.opts()
        ) :: {:ok, t()} | {:error, :oidcc_device_authorization.error()}
  def authorize(client_context, opts \\ %{}) do
    client_context = ClientContext.struct_to_record(client_context)

    with {:ok, authorization} <- :oidcc_device_authorization.authorize(client_context, opts) do
      {:ok, record_to_struct(authorization)}
    end
  end

  @doc false
  @spec authorization_to_record(authorization :: t() | String.t()) ::
          :oidcc_device_authorization.t() | binary()
  def authorization_to_record(device_code) when is_binary(device_code), do: device_code
  def authorization_to_record(%__MODULE__{} = authorization), do: struct_to_record(authorization)
end
