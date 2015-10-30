%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

-module(ppp_session).

-behaviour(regine_server).

%% API
-export([start_link/0, new/6, lookup/1, lookup/2]).

%% regine_server callbacks
-export([init/1, handle_register/4, handle_unregister/3, handle_pid_remove/3, handle_death/3, terminate/2]).

-define(SERVER, ?MODULE). 

-record(state, {
         }).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    regine_server:start_link({local, ?SERVER}, ?MODULE, []).

new(HandlerMod, HandlerPid, HandlerInfo, PeerId, SessionId, PPPConfig) ->
    {ok, Session} = ppp_link_sup:new(HandlerMod, HandlerPid, HandlerInfo, PPPConfig),
    io:format("new Session: ~p, ~p~n", [SessionId, Session]),
    regine_server:register(?SERVER, Session, PeerId, {PeerId, SessionId}),
    {ok, Session}.

lookup(PeerId, SessionId) ->
    lookup({PeerId, SessionId}).

lookup(SessionId) ->
    io:format("session lookup: ~p~n", [ets:lookup(?SERVER, SessionId)]),
    case ets:lookup(?SERVER, SessionId) of
	[] ->
	    false;
	[{SessionId, Session}] ->
	    Session
    end.

%%%===================================================================
%%% regine_server functions
%%%===================================================================

init([]) ->
    process_flag(trap_exit, true),
    ets:new(?SERVER, [bag, protected, named_table, {read_concurrency, true}]),
    {ok, #state{}}.

handle_register(Pid, SessionId, OtherSessionId, State) ->
    List = [SessionId|[OtherSessionId || OtherSessionId /= undefined]],
    ets:insert(?SERVER, [{Id, Pid} || Id <- List]),
    {ok, List, State}.

handle_unregister(SessionId, OtherSessionId, State) ->
    Pids = ets:lookup(?SERVER, SessionId),
    ets:delete(?SERVER, SessionId),
    if OtherSessionId /= undefined ->
	    ets:delete(?SERVER, OtherSessionId);
       true ->
	    ok
    end,
    {Pids, State}.

handle_death(_Pid, _Reason, State) ->
    State.

handle_pid_remove(Pid, SessionIds, State) ->
    lists:foreach(fun(SessionId) -> ets:delete_object(?SERVER, {SessionId, Pid}) end, SessionIds),
    State.

terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================
