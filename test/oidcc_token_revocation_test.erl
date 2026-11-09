%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_token_revocation_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("oidcc/include/oidcc_client_context.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").

revoke_raw_token_test() ->
    {ClientContext, Endpoint} = client_context(<<"client_secret">>),
    Self = self(),
    HttpFun = respond(Self, Endpoint, {{"HTTP/1.1", 200, "OK"}, [], <<>>}),

    ?assertEqual(
        ok, oidcc_token_revocation:revoke(<<"access_token">>, ClientContext, opts(HttpFun))
    ),

    {Header, Body} = received(),
    ?assertEqual(<<"access_token">>, proplists:get_value(<<"token">>, Body)),
    ?assertEqual(undefined, proplists:get_value(<<"token_type_hint">>, Body)),
    ?assertMatch({"authorization", _}, lists:keyfind("authorization", 1, Header)).

revoke_token_record_prefers_refresh_test() ->
    {ClientContext, Endpoint} = client_context(<<"client_secret">>),
    Self = self(),
    HttpFun = respond(Self, Endpoint, {{"HTTP/1.1", 200, "OK"}, [], <<>>}),
    Token = #oidcc_token{
        id = none,
        access = #oidcc_token_access{token = <<"access_token">>},
        refresh = #oidcc_token_refresh{token = <<"refresh_token">>},
        scope = []
    },

    ?assertEqual(ok, oidcc_token_revocation:revoke(Token, ClientContext, opts(HttpFun))),

    {_Header, Body} = received(),
    ?assertEqual(<<"refresh_token">>, proplists:get_value(<<"token">>, Body)),
    ?assertEqual(<<"refresh_token">>, proplists:get_value(<<"token_type_hint">>, Body)).

revoke_token_record_without_refresh_test() ->
    {ClientContext, Endpoint} = client_context(<<"client_secret">>),
    Self = self(),
    HttpFun = respond(Self, Endpoint, {{"HTTP/1.1", 200, "OK"}, [], <<>>}),
    Token = #oidcc_token{
        id = none,
        access = #oidcc_token_access{token = <<"access_token">>},
        refresh = none,
        scope = []
    },

    ?assertEqual(ok, oidcc_token_revocation:revoke(Token, ClientContext, opts(HttpFun))),

    {_Header, Body} = received(),
    ?assertEqual(<<"access_token">>, proplists:get_value(<<"token">>, Body)),
    ?assertEqual(<<"access_token">>, proplists:get_value(<<"token_type_hint">>, Body)).

revoke_explicit_hint_wins_test() ->
    {ClientContext, Endpoint} = client_context(<<"client_secret">>),
    Self = self(),
    HttpFun = respond(Self, Endpoint, {{"HTTP/1.1", 200, "OK"}, [], <<>>}),

    ?assertEqual(
        ok,
        oidcc_token_revocation:revoke(
            #oidcc_token_access{token = <<"token">>},
            ClientContext,
            (opts(HttpFun))#{token_type_hint => refresh_token}
        )
    ),

    {_Header, Body} = received(),
    ?assertEqual(<<"refresh_token">>, proplists:get_value(<<"token_type_hint">>, Body)).

revoke_accepts_any_success_body_test() ->
    {ClientContext, Endpoint} = client_context(<<"client_secret">>),
    Self = self(),
    Responses = [
        {{"HTTP/1.1", 200, "OK"}, [{"content-type", "text/plain"}], <<"revoked">>},
        {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], <<>>},
        {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], <<"{}">>}
    ],
    lists:foreach(
        fun(Response) ->
            HttpFun = respond(Self, Endpoint, Response),
            ?assertEqual(
                ok, oidcc_token_revocation:revoke(<<"token">>, ClientContext, opts(HttpFun))
            ),
            received()
        end,
        Responses
    ).

revoke_unauthenticated_client_uses_none_test() ->
    %% The fixture advertises only client_secret_basic for revocation; a client
    %% without a secret must still identify itself with client_id.
    {ClientContext, Endpoint} = client_context(unauthenticated),
    Self = self(),
    HttpFun = respond(Self, Endpoint, {{"HTTP/1.1", 200, "OK"}, [], <<>>}),

    ?assertEqual(ok, oidcc_token_revocation:revoke(<<"token">>, ClientContext, opts(HttpFun))),

    {Header, Body} = received(),
    ?assertEqual(<<"client_id">>, proplists:get_value(<<"client_id">>, Body)),
    ?assertEqual(undefined, proplists:get_value(<<"client_secret">>, Body)),
    ?assertEqual(false, lists:keyfind("authorization", 1, Header)).

revoke_error_response_test() ->
    {ClientContext, Endpoint} = client_context(<<"client_secret">>),
    Self = self(),
    HttpFun = respond(
        Self,
        Endpoint,
        {
            {"HTTP/1.1", 400, "Bad Request"},
            [{"content-type", "application/json"}],
            <<"{\"error\":\"unsupported_token_type\"}">>
        }
    ),

    ?assertEqual(
        {error, {http_error, 400, #{<<"error">> => <<"unsupported_token_type">>}}},
        oidcc_token_revocation:revoke(<<"token">>, ClientContext, opts(HttpFun))
    ),
    received().

revocation_not_supported_test() ->
    {ClientContext0, _Endpoint} = client_context(<<"client_secret">>),
    #oidcc_client_context{provider_configuration = Configuration} = ClientContext0,
    ClientContext = ClientContext0#oidcc_client_context{
        provider_configuration = Configuration#oidcc_provider_configuration{
            revocation_endpoint = undefined
        }
    },

    ?assertEqual(
        {error, revocation_not_supported},
        oidcc_token_revocation:revoke(<<"token">>, ClientContext, #{})
    ).

client_context(ClientSecret) ->
    PrivDir = code:priv_dir(oidcc),
    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, #oidcc_provider_configuration{revocation_endpoint = Endpoint} = Configuration} =
        oidcc_provider_configuration:decode_configuration(json:decode(ConfigurationBinary)),
    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    {
        oidcc_client_context:from_manual(Configuration, Jwks, <<"client_id">>, ClientSecret),
        Endpoint
    }.

respond(Self, Endpoint, Response) ->
    fun(
        post,
        {ReqEndpoint, Header, "application/x-www-form-urlencoded", Body},
        _HttpOptions,
        _RequestOptions,
        _AdapterConfig
    ) ->
        Endpoint = ReqEndpoint,
        Self ! {revoke_request, Header, uri_string:dissect_query(Body)},
        {ok, Response}
    end.

received() ->
    receive
        {revoke_request, Header, Body} -> {Header, Body}
    after 0 -> error(no_request)
    end.

opts(HttpFun) ->
    #{request_opts => #{http_adapter => {oidcc_http_adapter_test, #{request => HttpFun}}}}.
