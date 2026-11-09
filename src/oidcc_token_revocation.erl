%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_token_revocation).

-feature(maybe_expr, enable).

-moduledoc """
OAuth 2.0 Token Revocation.

See https://datatracker.ietf.org/doc/html/rfc7009.

## Telemetry

See [`Oidcc.TokenRevocation`](`m:'Elixir.Oidcc.TokenRevocation'`).
""".
-moduledoc #{since => <<"3.10.0">>}.

-include("oidcc_client_context.hrl").
-include("oidcc_provider_configuration.hrl").
-include("oidcc_token.hrl").

-export([revoke/3]).

-export_type([error/0]).
-export_type([opts/0]).
-export_type([token_type_hint/0]).

-doc """
Hint about the type of the token being revoked.

See https://datatracker.ietf.org/doc/html/rfc7009#section-2.1.
""".
-doc #{since => <<"3.10.0">>}.
-type token_type_hint() :: access_token | refresh_token.

-doc """
Options for `revoke/3`.

* `token_type_hint` - sent as `token_type_hint`. Set automatically when a
  token record is passed; an explicit value takes precedence.
* `preferred_auth_methods` - client authentication methods to try, in order.
* `request_opts` - HTTP request options, see `t:oidcc_http_util:request_opts/0`.
* `dpop_nonce` - DPoP nonce to use for the request.
""".
-doc #{since => <<"3.10.0">>}.
-type opts() :: #{
    token_type_hint => token_type_hint(),
    preferred_auth_methods => [oidcc_auth_util:auth_method(), ...],
    request_opts => oidcc_http_util:request_opts(),
    dpop_nonce => binary()
}.

-doc #{since => <<"3.10.0">>}.
-type error() ::
    revocation_not_supported
    | oidcc_auth_util:error()
    | oidcc_http_util:error().

-telemetry_event(#{
    event => [oidcc, revoke_token, start],
    description => <<"Emitted at the start of revoking the token">>,
    measurements => <<"#{system_time => non_neg_integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, revoke_token, stop],
    description => <<"Emitted at the end of revoking the token">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-telemetry_event(#{
    event => [oidcc, revoke_token, exception],
    description => <<"Emitted at the end of revoking the token">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string(), client_id => binary()}">>
}).

-doc """
Revoke the given token.

Accepts a raw token, an access or refresh token record, or a full
`t:oidcc_token:t/0`. For a full token the refresh token is revoked when
present, since RFC 7009 §2.1 has the authorization server also invalidate
the access tokens issued under the same grant; otherwise the access token
is revoked.

The server answers `200` both when the token was revoked and when it was
already invalid or unknown (RFC 7009 §2.2), so `ok` does not mean the token
was valid.

A client without a secret (an unauthenticated client context) can only
identify itself with `client_id`, so it always authenticates with `none`,
whatever `revocation_endpoint_auth_methods_supported` advertises.

For a high level interface using `m:oidcc_provider_configuration_worker`
see `oidcc:revoke_token/5`.

## Examples

```erlang
{ok, ClientContext} =
  oidcc_client_context:from_configuration_worker(provider_name,
                                                 <<"client_id">>,
                                                 <<"client_secret">>),

%% Get Token

ok = oidcc_token_revocation:revoke(Token, ClientContext, #{}).
```
""".
-doc #{since => <<"3.10.0">>}.
-spec revoke(Token, ClientContext, Opts) -> ok | {error, error()} when
    Token ::
        oidcc_token:t()
        | oidcc_token:access()
        | oidcc_token:refresh()
        | binary(),
    ClientContext :: oidcc_client_context:t(),
    Opts :: opts().
revoke(#oidcc_token{refresh = #oidcc_token_refresh{} = Refresh}, ClientContext, Opts) ->
    revoke(Refresh, ClientContext, Opts);
revoke(#oidcc_token{access = #oidcc_token_access{} = Access}, ClientContext, Opts) ->
    revoke(Access, ClientContext, Opts);
revoke(#oidcc_token_refresh{token = Token}, ClientContext, Opts) ->
    revoke(Token, ClientContext, maps:merge(#{token_type_hint => refresh_token}, Opts));
revoke(#oidcc_token_access{token = Token}, ClientContext, Opts) ->
    revoke(Token, ClientContext, maps:merge(#{token_type_hint => access_token}, Opts));
revoke(Token, ClientContext, Opts) when is_binary(Token) ->
    #oidcc_client_context{
        provider_configuration = Configuration,
        client_id = ClientId,
        client_secret = ClientSecret
    } = ClientContext,
    #oidcc_provider_configuration{
        revocation_endpoint = Endpoint0,
        issuer = Issuer,
        revocation_endpoint_auth_methods_supported = AdvertisedAuthMethods,
        revocation_endpoint_auth_signing_alg_values_supported = AllowAlgorithms
    } = Configuration,

    case Endpoint0 of
        undefined ->
            {error, revocation_not_supported};
        _ ->
            SupportedAuthMethods =
                case ClientSecret of
                    unauthenticated -> [<<"none">>];
                    _ -> AdvertisedAuthMethods
                end,
            Header0 = [],
            Body0 =
                [{<<"token">>, Token}] ++
                    case Opts of
                        #{token_type_hint := Hint} ->
                            [{<<"token_type_hint">>, atom_to_binary(Hint)}];
                        _ ->
                            []
                    end,

            RequestOpts = maps:get(request_opts, Opts, #{}),
            TelemetryOpts = #{
                topic => [oidcc, revoke_token],
                extra_meta => #{issuer => Issuer, client_id => ClientId}
            },
            DpopOpts =
                case Opts of
                    #{dpop_nonce := DpopNonce} ->
                        #{nonce => DpopNonce};
                    _ ->
                        #{}
                end,
            maybe
                {ok, {Body, Header1}, AuthMethod} ?=
                    oidcc_auth_util:add_client_authentication(
                        Body0, Header0, SupportedAuthMethods, AllowAlgorithms, Opts, ClientContext
                    ),
                Endpoint = oidcc_auth_util:maybe_mtls_endpoint(
                    Endpoint0,
                    AuthMethod,
                    <<"revocation_endpoint">>,
                    ClientContext
                ),
                Header = oidcc_auth_util:add_dpop_proof_header(
                    Header1, post, Endpoint, DpopOpts, ClientContext
                ),
                Request =
                    {Endpoint, Header, "application/x-www-form-urlencoded",
                        uri_string:compose_query(Body)},
                %% RFC 7009 §2.2: the success response carries no meaningful body
                {ok, {{raw, _Body}, _Headers}} ?=
                    oidcc_http_util:request(
                        post, Request, TelemetryOpts, RequestOpts, #{success_body => any}
                    ),
                ok
            else
                {error, {use_dpop_nonce, NewDpopNonce, _}} when
                    DpopOpts =:= #{}
                ->
                    %% only retry automatically if we didn't use a nonce the first time
                    %% (to avoid infinite loops)
                    revoke(Token, ClientContext, Opts#{dpop_nonce => NewDpopNonce});
                {error, Reason} ->
                    {error, Reason}
            end
    end.
