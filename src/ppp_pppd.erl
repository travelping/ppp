%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

-module(ppp_pppd).

-behaviour(gen_server).

%% API
-export([start_link/1]).
-export([send/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include_lib("kernel/include/logger.hrl").

-define(SERVER, ?MODULE). 

-record(state, {port, connection}).

%%%===================================================================
%%% API
%%%===================================================================

send(TransportPid, _TransportRef, Packet) ->
    gen_server:call(TransportPid, {send, Packet}).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Role) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Role], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([Role]) ->
    Args = gen_opts() ++ role_opts(Role),
    Port = open_port({spawn_executable, "/usr/sbin/pppd"}, [exit_status, binary, {args, Args}]),
    {ok, Connection} = ppp_link:start_link(?MODULE, self(), [], []),
    {ok, #state{port = Port, connection = Connection}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call({send, Packet}, _From, State = #state{port = Port}) ->
    Data = ppp_hdlc:encapsulate([{16#ff, 16#03, Packet}]),
    port_command(Port, Data),
    {reply, ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(Msg, State) ->
    ?LOG(debug, "pppd Cast: ~p", [Msg]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info({Port, {data, Data}}, State = #state{port = Port, connection = Connection}) ->
    ?LOG(debug, "pppd Data: ~p", [Data]),
    HDLC = ppp_hdlc:decapsulate(Data),
    lists:foreach(fun({_Address, _Control, PPP}) -> ppp_link:packet_in(Connection, PPP) end, HDLC),
    {noreply, State};

handle_info({Port, {exit_status, Status}}, State = #state{port = Port}) ->
    ?LOG(debug, "pppd existed with: ~p", [Status]),
    {stop, normal, State};

handle_info(Info, State) ->
    ?LOG(debug, "pppd Info: ~p", [Info]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ?LOG(debug, "ppp_pppd ~p terminated", [self()]),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

gen_opts() ->
    [
     "nodetach",
     "debug",
     "notty",
     "default-asyncmap",
     "lcp-max-configure", "1",
     "lcp-echo-failure", "3",
     "lcp-echo-interval", "10",
     "lcp-echo-adaptive",
     "mtu", "1492",
     "mru", "1492",
     "noaccomp",
     "nodeflate",
     "noccp",
     "novj",
     "novjccomp",
     "refuse-eap",
     "refuse-chap",
     "refuse-mschap",
     "refuse-mschap-v2"
].

role_opts(server) ->
    [
     "silent",
     "passive",
     "auth",
     "ms-dns", "192.168.13.7",
     "192.168.13.54:192.168.54.1"
    ];

role_opts(client) ->
    [
     "noauth",
     "usepeerdns",
     "user", "erlang",
     "password", "erlang"
    ].
