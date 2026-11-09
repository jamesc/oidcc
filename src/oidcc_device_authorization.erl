%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_device_authorization).

-feature(maybe_expr, enable).

-moduledoc """
OAuth 2.0 Device Authorization Grant.

See https://datatracker.ietf.org/doc/html/rfc8628.

`authorize/2` starts the flow (RFC 8628 Section 3.1). Show the user the
`user_code` and `verification_uri` (or `verification_uri_complete`), then
poll `oidcc_token:retrieve_device_token/3` every `interval` seconds until it
returns a token or a terminal error (Section 3.4).

## Records

To use the records, import the definition:

```erlang
-include_lib(["oidcc/include/oidcc_device_authorization.hrl"]).
```

## Telemetry

See [`Oidcc.DeviceAuthorization`](`m:'Elixir.Oidcc.DeviceAuthorization'`).
""".
-moduledoc #{since => <<"3.10.0">>}.

-include("oidcc_client_context.hrl").
-include("oidcc_device_authorization.hrl").
-include("oidcc_provider_configuration.hrl").

-export([authorize/2]).

-export_type([error/0]).
-export_type([opts/0]).
-export_type([t/0]).

-doc """
Device Authorization Response.

See https://datatracker.ietf.org/doc/html/rfc8628#section-3.2.

`interval` defaults to 5 seconds when the server omits it. Unknown response
fields are kept in `extra`.
""".
-doc #{since => <<"3.10.0">>}.
-type t() :: #oidcc_device_authorization{
    device_code :: binary(),
    user_code :: binary(),
    verification_uri :: uri_string:uri_string(),
    verification_uri_complete :: uri_string:uri_string() | undefined,
    expires_in :: pos_integer(),
    interval :: pos_integer(),
    extra :: #{binary() => term()}
}.

-doc """
Options for `authorize/2`.

* `scope` - scopes to request.
* `preferred_auth_methods` - client authentication methods to try, in order.
* `request_opts` - HTTP request options, see `t:oidcc_http_util:request_opts/0`.
* `body_extension` - extra form parameters for the request.
""".
-doc #{since => <<"3.10.0">>}.
-type opts() :: #{
    scope => oidcc_scope:scopes(),
    preferred_auth_methods => [oidcc_auth_util:auth_method(), ...],
    request_opts => oidcc_http_util:request_opts(),
    body_extension => oidcc_http_util:query_params()
}.

-doc #{since => <<"3.10.0">>}.
-type error() ::
    device_authorization_not_supported
    | {invalid_property, {Field :: binary(), GivenValue :: term()}}
    | oidcc_auth_util:error()
    | oidcc_http_util:error().

-telemetry_event(#{
    event => [oidcc, device_authorization, start],
    description => <<"Emitted at the start of requesting a device authorization">>,
    measurements => <<"#{system_time => non_neg_integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, device_authorization, stop],
    description => <<"Emitted at the end of requesting a device authorization">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, device_authorization, exception],
    description => <<"Emitted at the end of requesting a device authorization">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-doc """
Start a device authorization (RFC 8628 Section 3.1).

The client authenticates as it would at the token endpoint. A client
without a secret (an unauthenticated client context) identifies itself with
`client_id` only (`none`), whatever the provider advertises.

Support is signalled by `device_authorization_endpoint` in the provider
configuration. `grant_types_supported` is not checked: some providers
support the grant while advertising a non-standard grant type name. For a
provider that omits the endpoint from its discovery document, set it with
the `document_overrides` quirk.

## Examples

```erlang
{ok, ClientContext} =
  oidcc_client_context:from_configuration_worker(provider_name,
                                                 <<"client_id">>,
                                                 unauthenticated),

{ok, #oidcc_device_authorization{user_code = UserCode,
                                 verification_uri = Uri} = Authorization} =
  oidcc_device_authorization:authorize(ClientContext, #{scope => [<<"openid">>]}),

%% Show UserCode and Uri to the user, then poll
%% oidcc_token:retrieve_device_token(Authorization, ClientContext, #{})
```
""".
-doc #{since => <<"3.10.0">>}.
-spec authorize(ClientContext, Opts) -> {ok, t()} | {error, error()} when
    ClientContext :: oidcc_client_context:t(),
    Opts :: opts().
authorize(ClientContext, Opts) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        client_id = ClientId,
        client_secret = ClientSecret
    } = ClientContext,
    #oidcc_provider_configuration{
        device_authorization_endpoint = Endpoint0,
        issuer = Issuer,
        token_endpoint_auth_methods_supported = AdvertisedAuthMethods,
        token_endpoint_auth_signing_alg_values_supported = AllowAlgorithms
    } = Configuration,

    case Endpoint0 of
        undefined ->
            {error, device_authorization_not_supported};
        _ ->
            SupportedAuthMethods =
                case ClientSecret of
                    unauthenticated -> [<<"none">>];
                    _ -> AdvertisedAuthMethods
                end,
            Header0 = [{"accept", "application/json"}],
            Scope = maps:get(scope, Opts, []),
            Body0 =
                oidcc_scope:query_append_scope(Scope, []) ++
                    maps:get(body_extension, Opts, []),
            RequestOpts = maps:get(request_opts, Opts, #{}),
            TelemetryOpts = #{
                topic => [oidcc, device_authorization],
                extra_meta => #{issuer => Issuer, client_id => ClientId}
            },
            maybe
                {ok, {Body, Header}, AuthMethod} ?=
                    oidcc_auth_util:add_client_authentication(
                        Body0, Header0, SupportedAuthMethods, AllowAlgorithms, Opts, ClientContext
                    ),
                Endpoint = oidcc_auth_util:maybe_mtls_endpoint(
                    Endpoint0, AuthMethod, <<"device_authorization_endpoint">>, ClientContext
                ),
                Request =
                    {Endpoint, Header, "application/x-www-form-urlencoded",
                        uri_string:compose_query(Body)},
                {ok, {{json, Response}, _Headers}} ?=
                    oidcc_http_util:request(post, Request, TelemetryOpts, RequestOpts),
                extract_response(Response)
            end
    end.

-spec extract_response(Response :: term()) -> {ok, t()} | {error, error()}.
extract_response(
    #{
        <<"device_code">> := DeviceCode,
        <<"user_code">> := UserCode,
        <<"verification_uri">> := VerificationUri,
        <<"expires_in">> := ExpiresIn
    } = Response
) when
    is_binary(DeviceCode),
    is_binary(UserCode),
    is_binary(VerificationUri),
    is_integer(ExpiresIn),
    ExpiresIn > 0
->
    maybe
        {ok, Interval} ?= extract_interval(Response),
        {ok, VerificationUriComplete} ?= extract_verification_uri_complete(Response),
        {ok, #oidcc_device_authorization{
            device_code = DeviceCode,
            user_code = UserCode,
            verification_uri = VerificationUri,
            verification_uri_complete = VerificationUriComplete,
            expires_in = ExpiresIn,
            interval = Interval,
            extra = maps:without(
                [
                    <<"device_code">>,
                    <<"user_code">>,
                    <<"verification_uri">>,
                    <<"verification_uri_complete">>,
                    <<"expires_in">>,
                    <<"interval">>
                ],
                Response
            )
        }}
    end;
extract_response(Response) when is_map(Response) ->
    Missing = [
        Field
     || Field <- [
            <<"device_code">>, <<"user_code">>, <<"verification_uri">>, <<"expires_in">>
        ],
        not is_map_key(Field, Response)
    ],
    case Missing of
        [Field | _] -> {error, {invalid_property, {Field, undefined}}};
        [] -> {error, {invalid_property, {<<"device_authorization_response">>, Response}}}
    end;
extract_response(Response) ->
    {error, {invalid_property, {<<"device_authorization_response">>, Response}}}.

-spec extract_interval(Response :: map()) -> {ok, pos_integer()} | {error, error()}.
extract_interval(#{<<"interval">> := Interval}) when is_integer(Interval), Interval > 0 ->
    {ok, Interval};
extract_interval(#{<<"interval">> := Interval}) ->
    {error, {invalid_property, {<<"interval">>, Interval}}};
extract_interval(#{}) ->
    %% RFC 8628 Section 3.2: "If no value is provided, clients MUST use 5 as
    %% the default."
    {ok, 5}.

-spec extract_verification_uri_complete(Response :: map()) ->
    {ok, uri_string:uri_string() | undefined} | {error, error()}.
extract_verification_uri_complete(#{<<"verification_uri_complete">> := Uri}) when
    is_binary(Uri)
->
    {ok, Uri};
extract_verification_uri_complete(#{<<"verification_uri_complete">> := Uri}) ->
    {error, {invalid_property, {<<"verification_uri_complete">>, Uri}}};
extract_verification_uri_complete(#{}) ->
    {ok, undefined}.
