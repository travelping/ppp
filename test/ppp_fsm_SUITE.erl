%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

-module(ppp_fsm_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").

%%%===================================================================
%%% API
%%%===================================================================

all() ->
    [test_fsm].

init_per_suite(Config) ->
    ct_property_test:init_per_suite(Config).

end_per_suite(_Config) ->
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

%%--------------------------------------------------------------------
test_fsm() ->
    [{doc, "Check that the PPP FSM works"}].
test_fsm(Config) ->
    ct_property_test:quickcheck(ppp_fsm_prop:fsm_prop(Config), Config).
