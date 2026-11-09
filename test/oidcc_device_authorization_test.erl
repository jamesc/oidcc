%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_device_authorization_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("oidcc/include/oidcc_client_context.hrl").
-include_lib("oidcc/include/oidcc_device_authorization.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").

-define(DEVICE_ENDPOINT, <<"https://my.provider/device">>).
-define(TOKEN_ENDPOINT, <<"https://my.provider/token">>).
-define(DEVICE_GRANT, <<"urn:ietf:params:oauth:grant-type:device_code">>).

decode_configuration_test() ->
    {ok, ConfigurationBinary} = file:read_file(
        code:priv_dir(oidcc) ++ "/test/fixtures/example-metadata.json"
    ),
    Document = maps:put(
        <<"device_authorization_endpoint">>, ?DEVICE_ENDPOINT, json:decode(ConfigurationBinary)
    ),
    {ok, #oidcc_provider_configuration{
        device_authorization_endpoint = Endpoint, extra_fields = ExtraFields
    }} =
        oidcc_provider_configuration:decode_configuration(Document),
    ?assertEqual(?DEVICE_ENDPOINT, Endpoint),
    ?assertNot(is_map_key(<<"device_authorization_endpoint">>, ExtraFields)).

authorize_unauthenticated_test() ->
    ClientContext = client_context(unauthenticated),
    HttpFun = respond(
        ?DEVICE_ENDPOINT,
        json(200, #{
            <<"device_code">> => <<"device_code">>,
            <<"user_code">> => <<"ABCD-EFGH">>,
            <<"verification_uri">> => <<"https://my.provider/activate">>,
            <<"verification_uri_complete">> =>
                <<"https://my.provider/activate?user_code=ABCD-EFGH">>,
            <<"expires_in">> => 900,
            <<"interval">> => 10,
            <<"custom">> => <<"value">>
        })
    ),

    ?assertEqual(
        {ok, #oidcc_device_authorization{
            device_code = <<"device_code">>,
            user_code = <<"ABCD-EFGH">>,
            verification_uri = <<"https://my.provider/activate">>,
            verification_uri_complete = <<"https://my.provider/activate?user_code=ABCD-EFGH">>,
            expires_in = 900,
            interval = 10,
            extra = #{<<"custom">> => <<"value">>}
        }},
        oidcc_device_authorization:authorize(
            ClientContext, (opts(HttpFun))#{scope => [<<"openid">>, <<"profile">>]}
        )
    ),

    {Header, Body} = received(),
    ?assertEqual(<<"client_id">>, proplists:get_value(<<"client_id">>, Body)),
    ?assertEqual(<<"openid profile">>, proplists:get_value(<<"scope">>, Body)),
    ?assertEqual(undefined, proplists:get_value(<<"client_secret">>, Body)),
    ?assertEqual(false, lists:keyfind("authorization", 1, Header)).

authorize_confidential_client_authenticates_test() ->
    ClientContext = client_context(<<"client_secret">>),
    HttpFun = respond(?DEVICE_ENDPOINT, json(200, minimal_response())),

    ?assertMatch(
        {ok, #oidcc_device_authorization{}},
        oidcc_device_authorization:authorize(ClientContext, opts(HttpFun))
    ),

    %% the fixture's preferred token endpoint method is client_secret_post
    {_Header, Body} = received(),
    ?assertEqual(<<"client_secret">>, proplists:get_value(<<"client_secret">>, Body)).

authorize_defaults_test() ->
    ClientContext = client_context(unauthenticated),
    HttpFun = respond(?DEVICE_ENDPOINT, json(200, minimal_response())),

    ?assertMatch(
        {ok, #oidcc_device_authorization{
            interval = 5, verification_uri_complete = undefined, extra = #{}
        }},
        oidcc_device_authorization:authorize(ClientContext, opts(HttpFun))
    ),
    received().

authorize_invalid_response_test() ->
    ClientContext = client_context(unauthenticated),
    lists:foreach(
        fun({Response, Expected}) ->
            HttpFun = respond(?DEVICE_ENDPOINT, json(200, Response)),
            ?assertEqual(
                {error, {invalid_property, Expected}},
                oidcc_device_authorization:authorize(ClientContext, opts(HttpFun))
            ),
            received()
        end,
        [
            {maps:remove(<<"user_code">>, minimal_response()), {<<"user_code">>, undefined}},
            {(minimal_response())#{<<"interval">> => 0}, {<<"interval">>, 0}},
            {
                (minimal_response())#{<<"verification_uri_complete">> => 42},
                {<<"verification_uri_complete">>, 42}
            }
        ]
    ).

authorize_not_supported_test() ->
    ClientContext0 = client_context(unauthenticated),
    #oidcc_client_context{provider_configuration = Configuration} = ClientContext0,
    ClientContext = ClientContext0#oidcc_client_context{
        provider_configuration = Configuration#oidcc_provider_configuration{
            device_authorization_endpoint = undefined
        }
    },
    ?assertEqual(
        {error, device_authorization_not_supported},
        oidcc_device_authorization:authorize(ClientContext, #{})
    ).

retrieve_device_token_test() ->
    ClientContext = client_context(unauthenticated),
    HttpFun = respond(
        ?TOKEN_ENDPOINT,
        json(200, #{
            <<"access_token">> => <<"access_token">>,
            <<"token_type">> => <<"Bearer">>,
            <<"expires_in">> => 3600,
            <<"refresh_token">> => <<"refresh_token">>
        })
    ),
    Authorization = #oidcc_device_authorization{
        device_code = <<"device_code">>,
        user_code = <<"ABCD-EFGH">>,
        verification_uri = <<"https://my.provider/activate">>,
        expires_in = 900
    },

    ?assertMatch(
        {ok, #oidcc_token{
            id = none,
            access = #oidcc_token_access{token = <<"access_token">>, expires = 3600},
            refresh = #oidcc_token_refresh{token = <<"refresh_token">>}
        }},
        oidcc_token:retrieve_device_token(Authorization, ClientContext, opts(HttpFun))
    ),

    {Header, Body} = received(),
    ?assertEqual(?DEVICE_GRANT, proplists:get_value(<<"grant_type">>, Body)),
    ?assertEqual(<<"device_code">>, proplists:get_value(<<"device_code">>, Body)),
    ?assertEqual(<<"client_id">>, proplists:get_value(<<"client_id">>, Body)),
    ?assertEqual(false, lists:keyfind("authorization", 1, Header)).

retrieve_device_token_errors_test() ->
    ClientContext = client_context(unauthenticated),
    lists:foreach(
        fun({Code, Expected}) ->
            HttpFun = respond(?TOKEN_ENDPOINT, json(400, #{<<"error">> => Code})),
            ?assertEqual(
                {error, Expected},
                oidcc_token:retrieve_device_token(<<"device_code">>, ClientContext, opts(HttpFun))
            ),
            received()
        end,
        [
            {<<"authorization_pending">>, authorization_pending},
            {<<"slow_down">>, slow_down},
            {<<"access_denied">>, access_denied},
            {<<"expired_token">>, expired_token},
            {<<"invalid_grant">>, {http_error, 400, #{<<"error">> => <<"invalid_grant">>}}}
        ]
    ).

client_context(ClientSecret) ->
    PrivDir = code:priv_dir(oidcc),
    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    {ok, Configuration} =
        oidcc_provider_configuration:decode_configuration(json:decode(ConfigurationBinary)),
    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk.pem"),
    oidcc_client_context:from_manual(
        Configuration#oidcc_provider_configuration{
            device_authorization_endpoint = ?DEVICE_ENDPOINT
        },
        Jwks,
        <<"client_id">>,
        ClientSecret
    ).

minimal_response() ->
    #{
        <<"device_code">> => <<"device_code">>,
        <<"user_code">> => <<"ABCD-EFGH">>,
        <<"verification_uri">> => <<"https://my.provider/activate">>,
        <<"expires_in">> => 900
    }.

json(Status, Body) ->
    {
        {"HTTP/1.1", Status, "Status"},
        [{"content-type", "application/json"}],
        iolist_to_binary(json:encode(Body))
    }.

respond(Endpoint, Response) ->
    Self = self(),
    fun(
        post,
        {ReqEndpoint, Header, "application/x-www-form-urlencoded", Body},
        _HttpOptions,
        _RequestOptions,
        _AdapterConfig
    ) ->
        Endpoint = iolist_to_binary(ReqEndpoint),
        Self ! {device_request, Header, uri_string:dissect_query(Body)},
        {ok, Response}
    end.

received() ->
    receive
        {device_request, Header, Body} -> {Header, Body}
    after 0 -> error(no_request)
    end.

opts(HttpFun) ->
    #{request_opts => #{http_adapter => {oidcc_http_adapter_test, #{request => HttpFun}}}}.
