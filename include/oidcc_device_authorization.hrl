%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-ifndef(OIDCC_DEVICE_AUTHORIZATION_HRL).

%% RFC 8628 Section 3.2 Device Authorization Response
-record(oidcc_device_authorization, {
    device_code :: binary(),
    user_code :: binary(),
    verification_uri :: uri_string:uri_string(),
    verification_uri_complete = undefined :: uri_string:uri_string() | undefined,
    expires_in :: pos_integer(),
    interval = 5 :: pos_integer(),
    extra = #{} :: #{binary() => term()}
}).

-define(OIDCC_DEVICE_AUTHORIZATION_HRL, 1).

-endif.
