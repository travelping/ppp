-module(ppp_link).

-behaviour(gen_fsm).

%% API
-export([start_link/4]).
-export([packet_in/2, send/2, link_down/1]).
-export([layer_up/3, layer_down/3, layer_started/3, layer_finished/3]).
-export([auth_withpeer/3, auth_peer/3]).
-export([accounting_on/0]).

%% RADIUS helper
-export([accounting_attrs/2]).

%% gen_fsm callbacks
-export([init/1,
	 establish/2, auth/2, network/2, terminating/2,
	 handle_event/3, handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).

-include("ppp.hrl").
-include("ppp_lcp.hrl").
-include("ppp_ipcp.hrl").
-include("ppp_ipv6cp.hrl").
-include_lib("eradius/include/eradius_lib.hrl").
-include_lib("eradius/include/dictionary.hrl").
-include_lib("eradius/include/dictionary_rfc4679.hrl").

-define(SERVER, ?MODULE).
-define(NETWORK_PROTOCOL_TIMEOUT, 5000).

-record(state, {
	  config		:: list(),         		%% config options proplist
	  transport		:: pid(), 			%% Transport Layer
	  transport_info	:: any(), 			%% Transport Layer Info
	  lcp			:: pid(), 			%% LCP protocol driver
	  pap			:: pid(), 			%% PAP protocol driver
	  ipcp			:: pid(), 			%% IPCP protocol driver
	  ipv6cp		:: pid(), 			%% IPv6CP protocol driver

	  auth_required = true	:: boolean,
	  auth_pending = []	:: [atom()],

	  nps_open = []		:: ordsets:ordset(),		%% List of Network Protocols that are open
	  nps_required = []	:: ordsets:ordset(),		%% List of required Network Protocols to establish

	  peerid = <<>>		:: binary(),
	  peer_addrs = []	:: orddict:orddict(),		%% List of Network Protocol Addresses

	  our_lcp_opts		:: #lcp_opts{}, 		%% Options that peer ack'd
	  his_lcp_opts		:: #lcp_opts{},			%% Options that we ack'd
								%% Accounting data
	  accounting_start	:: integer(),			%% Session Start Time in Ticks
	  timeout_ref		:: reference(),			%% Session-Timeout Timer
	  interim_ref		:: reference()			%% Interim-Accouting Timer
	 }).

%%%===================================================================
%%% API
%%%===================================================================

packet_in(Connection, Packet) ->
    gen_fsm:send_event(Connection, {packet_in, ppp_frame:decode(Packet)}).

send(Connection, Packet) ->
    gen_fsm:send_all_state_event(Connection, {packet_out, Packet}).

link_down(Connection) ->
    gen_fsm:send_event(Connection, link_down).

layer_up(Link, Layer, Info) ->
    gen_fsm:send_event(Link, {layer_up, Layer, Info}).

layer_down(Link, Layer, Info) ->
    gen_fsm:send_event(Link, {layer_down, Layer, Info}).

layer_started(Link, Layer, Info) ->
    gen_fsm:send_event(Link, {layer_started, Layer, Info}).

layer_finished(Link, Layer, Info) ->
    gen_fsm:send_event(Link, {layer_finished, Layer, Info}).

auth_withpeer(Link, Layer, Info) ->
    gen_fsm:send_event(Link, {auth_withpeer, Layer, Info}).

auth_peer(Link, Layer, Info) ->
    gen_fsm:send_event(Link, {auth_peer, Layer, Info}).

start_link(TransportModule, TransportPid, TransportRef, Config) ->
    gen_fsm:start_link(?MODULE, [{TransportModule, TransportRef}, TransportPid, Config], []).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

init([TransportInfo, TransportPid, Config]) ->
    process_flag(trap_exit, true),

    NPsRequired = ordsets:from_list([ipcp]),

    {ok, LCP} = ppp_lcp:start_link(self(), Config),
    {ok, PAP} = ppp_pap:start_link(self(), Config),
    ppp_lcp:loweropen(LCP),
    ppp_lcp:lowerup(LCP),
    {ok, establish, #state{config = Config, transport = TransportPid , transport_info = TransportInfo,
			   lcp = LCP, pap = PAP,
			   nps_required = NPsRequired, nps_open = ordsets:new(),
			   peer_addrs = orddict:new()}}.

establish({packet_in, Frame}, State = #state{lcp = LCP})
  when element(1, Frame) == lcp ->
    io:format("LCP Frame in phase establish: ~p~n", [Frame]),
    case ppp_lcp:frame_in(LCP, Frame) of
 	{up, OurOpts, HisOpts} ->
	    NewState0 = State#state{our_lcp_opts = OurOpts, his_lcp_opts = HisOpts},
	    lowerup(NewState0),
	    if
		OurOpts#lcp_opts.neg_auth /= [] orelse
		HisOpts#lcp_opts.neg_auth /= [] ->
		    NewState1 = do_auth_peer(OurOpts#lcp_opts.neg_auth, NewState0),
		    NewState2 = do_auth_withpeer(HisOpts#lcp_opts.neg_auth, NewState1),
		    {next_state, auth, NewState2};
		true ->
		    phase_open(network, NewState0)
	    end;
	Reply ->
	    io:format("LCP got: ~p~n", [Reply]),
	    {next_state, establish, State}
    end;

establish({packet_in, Frame}, State) ->
    %% RFC 1661, Sect. 3.4:
    %%   Any non-LCP packets received during this phase MUST be silently
    %%   discarded.
    io:format("non-LCP Frame in phase establish: ~p, ignoring~n", [Frame]),
    {next_state, establish, State};

establish(link_down, State) ->
    lcp_close(<<"Link down">>, State);

establish({layer_down, lcp, Reason}, State) ->
    lowerdown(State),
    lowerclose(Reason, State),
    lcp_down(State);

establish({layer_finished, lcp, terminated}, State) ->
    io:format("LCP in phase establish got: terminated~n"),
    %% TODO: might want to restart LCP.....
    {stop, normal, State}.

auth({packet_in, Frame}, State = #state{lcp = LCP})
  when element(1, Frame) == lcp ->
    io:format("LCP Frame in phase auth: ~p~n", [Frame]),
    case ppp_lcp:frame_in(LCP, Frame) of
 	down ->
	    lcp_down(State);
	Reply ->
	    io:format("LCP got: ~p~n", [Reply]),
	    {next_state, auth, State}
    end;

%% TODO: we might be able to start protocols on demand....
auth({packet_in, Frame}, State = #state{pap = PAP})
  when element(1, Frame) == pap ->
    io:format("PAP Frame in phase auth: ~p~n", [Frame]),
    case ppp_pap:frame_in(PAP, Frame) of
	ok ->
	    {next_state, auth, State};
	Reply when is_tuple(Reply) ->
	    io:format("PAP in phase auth got: ~p~n", [Reply]),
	    auth_reply(Reply, State)
    end;

auth({packet_in, Frame}, State) ->
    %% RFC 1661, Sect. 3.5:
    %%   Only Link Control Protocol, authentication protocol, and link quality
    %%   monitoring packets are allowed during this phase.  All other packets
    %%   received during this phase MUST be silently discarded.
    io:format("non-Auth Frame: ~p, ignoring~n", [Frame]),
    {next_state, auth, State};

auth({auth_peer, pap, fail}, State) ->
    lcp_close(<<"Authentication failed">>, State);

auth(link_down, State) ->
    lcp_close(<<"Link down">>, State).

network(interim_accounting, State) ->
    NewState = accounting_interim(State),
    {next_state, network, NewState};

network(session_timeout, State) ->
    NewState = stop_session_timeout(State),
    lcp_close(<<"Session Timeout">>, NewState);

network(network_protocol_timeout, State = #state{nps_required = NPsRequired, nps_open = NPsOpen}) ->
    case ordsets:is_subset(NPsRequired, NPsOpen) of
	true ->
	    {next_state, network, State};
	_ ->
	    lcp_close(<<"Network Protocols start-up timeout">>, State)
    end;

network({packet_in, Frame}, State = #state{lcp = LCP})
  when element(1, Frame) == lcp ->
    io:format("LCP Frame in phase network: ~p~n", [Frame]),
    case ppp_lcp:frame_in(LCP, Frame) of
 	down ->
	    State1 = accounting_stop(down, State),
	    lcp_down(State1);
	{rejected, Protocol}
	  when Protocol == ipcp;
	       Protocol == ipv6cp ->
	    network_protocol_down(Protocol, State);
	Reply ->
	    io:format("LCP got: ~p~n", [Reply]),
	    {next_state, network, State}
    end;

%% TODO: we might be able to start protocols on demand....
network({packet_in, Frame}, State = #state{ipcp = IPCP})
  when element(1, Frame) == ipcp, is_pid(IPCP) ->
    io:format("IPCP Frame in phase network: ~p~n", [Frame]),
    case ppp_ipcp:frame_in(IPCP, Frame) of
	down ->
	    network_protocol_down(ipcp, State);
	ok ->
	    {next_state, network, State};
 	{up, OurOpts, HisOpts} ->
	    network_protocol_up(ipcp, OurOpts, HisOpts, State);
	Reply when is_tuple(Reply) ->
	    io:format("IPCP in phase network got: ~p~n", [Reply]),
	    {next_state, network, State}
    end;

network({packet_in, Frame}, State = #state{ipv6cp = IPV6CP})
  when element(1, Frame) == ipv6cp, is_pid(IPV6CP) ->
    io:format("IPV6CP Frame in phase network: ~p~n", [Frame]),
    case ppp_ipv6cp:frame_in(IPV6CP, Frame) of
	down ->
	    network_protocol_down(ipv6cp, State);
	ok ->
	    {next_state, network, State};
 	{up, OurOpts, HisOpts} ->
	    network_protocol_up(ipv6cp, OurOpts, HisOpts, State);
	Reply when is_tuple(Reply) ->
	    io:format("IPV6CP in phase network got: ~p~n", [Reply]),
	    {next_state, network, State}
    end;

network({packet_in, Frame}, State) ->
    protocol_reject(Frame, State),
    {next_state, network, State};

network(link_down, State) ->
    lcp_close(<<"Link down">>, State);

network({layer_down, lcp, Reason}, State) ->
    State1 = accounting_stop(down, State),
    lowerdown(State1),
    lowerclose(Reason, State1),
    lcp_down(State1).

%% drain events
terminating({auth_peer, pap, fail}, State) ->
    {next_state, terminating, State};
terminating(interim_accounting, State) ->
    {next_state, terminating, State};
terminating(session_timeout, State) ->
    {next_state, terminating, State};
terminating(network_protocol_timeout, State) ->
    {next_state, terminating, State};

terminating({packet_in, Frame}, State = #state{lcp = LCP})
  when element(1, Frame) == lcp ->
    io:format("LCP Frame in phase terminating: ~p~n", [Frame]),
    case ppp_lcp:frame_in(LCP, Frame) of
	terminated ->
	    io:format("LCP in phase terminating got: terminated~n"),
	    %% TODO: might want to restart LCP.....
	    {stop, normal, State};
	Reply ->
	    io:format("LCP in phase terminating got: ~p~n", [Reply]),
	    {next_state, terminating, State}
    end;

terminating({packet_in, Frame}, State) ->
    %% RFC 1661, Sect. 3.4:
    %%   Any non-LCP packets received during this phase MUST be silently
    %%   discarded.
    io:format("non-LCP Frame in phase terminating: ~p, ignoring~n", [Frame]),
    {next_state, terminating, State};

terminating(link_down, State) ->
    {next_state, terminating, State};

terminating({layer_down, lcp, Reason}, State) ->
    State1 = accounting_stop(down, State),
    lowerdown(State1),
    lowerclose(Reason, State1),
    lcp_down(State1);

terminating({layer_finished, lcp, terminated}, State) ->
    io:format("LCP in phase terminating got: terminated~n"),
    %% TODO: might want to restart LCP.....
    transport_terminate(State),
    {stop, normal, State}.

handle_event({packet_out, Frame}, StateName, State) ->
    transport_send(State, Frame),
    {next_state, StateName, State};

handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

handle_sync_event(_Event, _From, StateName, State) ->
    Reply = ok,
    {reply, Reply, StateName, State}.

handle_info({'EXIT', Transport, _Reason}, _StateName, State = #state{transport = Transport}) ->
    io:format("Transport ~p terminated~n", [Transport]),
    State1 = accounting_stop(down, State),
    {stop, normal, State1};

handle_info(Info, StateName, State) ->
    io:format("~s: in state ~s, got info: ~p~n", [?MODULE, StateName, Info]),
    {next_state, StateName, State}.

terminate(_Reason, _StateName, _State) ->
    io:format("ppp_link ~p terminated~n", [self()]),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

protocol_reject(Request, #state{lcp = LCP}) ->
    ppp_lcp:protocol_reject(LCP, Request).

transport_send(#state{transport = Transport, transport_info = {TransportModule, TransportRef}}, Data) ->
    TransportModule:send(Transport, TransportRef, Data).

transport_terminate(#state{transport = Transport, transport_info = {TransportModule, TransportRef}}) ->
    TransportModule:terminate(Transport, TransportRef).

transport_get_acc_counter(_, undefined) ->
    [];
transport_get_acc_counter(#state{transport = Transport, transport_info = {TransportModule, TransportRef}}, [IP|_]) ->
    case TransportModule:get_counter(Transport, TransportRef, IP) of
	#ppp_stats{packet_count	= {PktRx, PktTx},
		   byte_count   = {CntRx, CntTx}} ->
	    [{?Acct_Output_Gigawords, CntTx div 16#100000000},
	     {?Acct_Input_Gigawords, CntRx div 16#100000000},
	     {?Acct_Output_Octets, CntTx rem 16#100000000},
	     {?Acct_Input_Octets, CntRx rem 16#100000000},
	     {?Acct_Output_Packets, PktTx},
	     {?Acct_Input_Packets, PktRx}];
	_ -> []
    end.
	

lowerup(#state{pap = PAP, ipcp = IPCP, ipv6cp = IPV6CP}) ->
    ppp_pap:lowerup(PAP),
    ppp_ipcp:lowerup(IPCP),
    ppp_ipv6cp:lowerup(IPV6CP),
    ok.

lowerdown(#state{pap = PAP, ipcp = IPCP, ipv6cp = IPV6CP}) ->
    ppp_pap:lowerdown(PAP),
    ppp_ipcp:lowerdown(IPCP),
    ppp_ipv6cp:lowerdown(IPV6CP),
    ok.

lowerclose(Reason, #state{pap = PAP, ipcp = IPCP, ipv6cp = IPV6CP}) ->
    ppp_pap:lowerclose(PAP, Reason),
    ppp_ipcp:lowerclose(IPCP, Reason),
    ppp_ipv6cp:lowerclose(IPV6CP, Reason),
    ok.

do_auth_peer([], State) ->
    State;
do_auth_peer([pap|_], State = #state{auth_pending = Pending, pap = PAP}) ->
    ppp_pap:auth_peer(PAP),
    State#state{auth_pending = [auth_peer|Pending]}.

do_auth_withpeer([], State) ->
    State;
do_auth_withpeer([pap|_], State = #state{auth_pending = Pending, pap = PAP}) ->
    ppp_pap:auth_withpeer(PAP, <<"">>, <<"">>),
    State#state{auth_pending = [auth_withpeer|Pending]}.

auth_success(Direction, State = #state{auth_pending = Pending}) ->
    NewState = State#state{auth_pending = proplists:delete(Direction, Pending)},
    if
	NewState#state.auth_pending == [] ->
	    phase_open(network, NewState);
	true ->
	    {next_state, auth, NewState}
    end.

auth_reply({auth_peer, success, PeerId, Opts}, State = #state{config = Config}) ->

    Config0 = lists:foldl(fun(Opt, Acc) ->
				  lists:keystore(element(1, Opt), 1, Acc, Opt)
			  end,
			  proplists:unfold(Config),
			  proplists:unfold(Opts)),
    Config1 = proplists:compact(Config0),
    NewState = State#state{config = Config1, peerid = PeerId},
    auth_success(auth_peer, NewState);

auth_reply({auth_peer, fail}, State) ->
    lcp_close(<<"Authentication failed">>, State);
    
auth_reply({auth_withpeer, success}, State) ->
    auth_success(auth_withpeer, State);
  
auth_reply({auth_withpeer, fail}, State) ->
    lcp_close(<<"Failed to authenticate ourselves to peer">>, State).

lcp_down(State) ->
    NewState = State#state{our_lcp_opts = undefined, his_lcp_opts = undefined},
    {next_state, terminating, NewState}.

lcp_close(Msg, State = #state{lcp = LCP}) ->
    Reply = ppp_lcp:lowerclose(LCP, Msg),
    io:format("LCP close got: ~p~n", [Reply]),
    {next_state, terminating, State}.

%% Network Phase Finished
phase_finished(network, State) ->
    lcp_close(<<"No network protocols running">>, State).

%% Network Phase Open
phase_open(network, State = #state{config = Config}) ->
    NewState1 = start_session_timeout(State),
    NewState2 = accounting_start(init, NewState1),
    {ok, IPCP} = ppp_ipcp:start_link(self(), Config),
    ppp_ipcp:lowerup(IPCP),
    ppp_ipcp:loweropen(IPCP),
    %% {ok, IPV6CP} = ppp_ipv6cp:start_link(self(), Config),
    %% ppp_ipv6cp:lowerup(IPV6CP),
    %% ppp_ipv6cp:loweropen(IPV6CP),
    IPV6CP = undefined,
    gen_fsm:send_event_after(?NETWORK_PROTOCOL_TIMEOUT, network_protocol_timeout),
    {next_state, network, NewState2#state{ipcp = IPCP, ipv6cp = IPV6CP}}.

network_protocol_up(Protocol, OurOpts, HisOpts, State) ->
    io:format("--------------------------~n~p is UP~n--------------------------~n", [Protocol]),
    NewState0 = State#state{nps_open = ordsets:add_element(Protocol, State#state.nps_open)},
    NewState1 = accounting_init(Protocol, OurOpts, HisOpts, NewState0),
    NewState2 = check_accounting_start(NewState1),
    {next_state, network, NewState2}.

network_protocol_down(Protocol, State = #state{nps_required = NPsRequired, nps_open = NPsOpen}) ->
    io:format("--------------------------~n~p is DOWN~n--------------------------~n", [Protocol]),
    NewState = State#state{nps_open = ordsets:del_element(Protocol, NPsOpen)},
    case ordsets:is_element(Protocol, NPsRequired) of
	true ->
	    %% a required Network Protocol is down, kill the entire link
	    Msg = iolist_to_binary(io_lib:format("network protocol ~p is required, but was rejected", [Protocol])),
	    lcp_close(Msg, NewState);
	_ ->
	    {next_state, network, NewState}
    end.

start_session_timeout(State = #state{config = Config}) ->
    case proplists:get_value(session_timeout, Config) of
	TimeOut when is_integer(TimeOut) ->
	    Ref = gen_fsm:send_event_after(TimeOut * 1000, session_timeout),
	    State#state{timeout_ref = Ref};
	_ ->
	    State
    end.

stop_session_timeout(State = #state{timeout_ref = Ref}) ->
    cancel_timer(Ref),
    State#state{timeout_ref = undefined}.

get_interim_accounting(Config) ->
    case proplists:get_value(interim_accounting, Config) of
	undefined ->
	    {ok, Value} = application:get_env(interim_accounting),
	    Value;
	Value ->
	    Value
    end.

accounting_init(ipcp, _OurOpts,
		_HisOpts = #ipcp_opts{hisaddr = HisAddr},
		State = #state{config = Config, peer_addrs = Addrs}) ->
    NewAddrs = orddict:append(ipcp, HisAddr, Addrs),
    NewConfig = append_accounting_attr({'Framed-IP-Address', HisAddr}, Config),
    State#state{config = NewConfig, peer_addrs = NewAddrs};
accounting_init(ipv6cp,	_OurOpts,
		_HisOpts = #ipv6cp_opts{hisid = HisId},
		State = #state{config = Config, peer_addrs = Addrs}) ->
    NewAddrs = orddict:append(ipv6cp, HisId, Addrs),
    NewConfig = append_accounting_attr({'Framed-Interface-Id', HisId}, Config),
    State#state{config = NewConfig, peer_addrs = NewAddrs}.

%% check wether all required Network Protocol are open, send Accounting Start if so
check_accounting_start(State = #state{nps_required = NPsRequired, nps_open = NPsOpen, accounting_start = undefined}) ->
    case ordsets:is_subset(NPsRequired, NPsOpen) of
	true ->
	    accounting_start(network_up, State);
	_ ->
	    State
    end;
check_accounting_start(State) ->
    State.

accounting_start(init, State) ->
    State;

accounting_start(network_up, State = #state{config = Config}) ->
    NewState0 = State#state{accounting_start = now_ticks()},
    io:format("--------------------------~nAccounting: OPEN~n--------------------------~n"),
    spawn(fun() -> do_accounting_start(NewState0) end),
    case get_interim_accounting(Config) of
	InterimAccounting when InterimAccounting > 0 ->
	    Ref = gen_fsm:send_event_after(InterimAccounting * 1000, interim_accounting),
	    NewState0#state{interim_ref = Ref};
	_ ->
	    NewState0
    end.

accounting_interim(State = #state{accounting_start = Start,
				  config = Config}) ->
    Now = now_ticks(),
    InterimAccounting = get_interim_accounting(Config) * 10,
    %% avoid time drifts...
    Next = InterimAccounting - (Now - Start) rem InterimAccounting,
    Ref = gen_fsm:send_event_after(InterimAccounting * 100, interim_accounting),

    io:format("--------------------------~nAccounting: Interim~nNext: ~p~n--------------------------~n", [Next]),
    spawn(fun() -> do_accounting_interim(Now, State) end),
    State#state{interim_ref = Ref}.

accounting_stop(_Reason,
		State = #state{interim_ref = Ref}) ->
    Now = now_ticks(),
    cancel_timer(Ref),
    spawn(fun() -> do_accounting_stop(Now, State) end),
    State#state{accounting_start = undefined, interim_ref = undefined}.

append_accounting_attr(Opt, Config) ->
    Accounting = proplists:get_value(accounting, Config, []),
    lists:keystore(accounting, 1, Config, {accounting, [Opt|Accounting]}).

accounting_attrs([], Attrs) ->
    Attrs;
accounting_attrs([{'Framed-IP-Address', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Framed_IP_Address, Value}|Attrs]);
accounting_attrs([{'Framed-Interface-Id', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Framed_Interface_Id, Value}|Attrs]);
accounting_attrs([{session_id, Value}|Rest], Attrs) ->
    Id = io_lib:format("~40.16.0B", [Value]),
    accounting_attrs(Rest, [{?Acct_Session_Id, Id}|Attrs]);
accounting_attrs([{class, Class}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Class, Class}|Attrs]);
accounting_attrs([{calling_station, Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Calling_Station_Id, Value}|Attrs]);
accounting_attrs([{called_station, Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Called_Station_Id, Value}|Attrs]);
accounting_attrs([{port_id, Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?NAS_Port_Id, Value}|Attrs]);

accounting_attrs([{port_type, pppoe_eth}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?NAS_Port_Type, 32}|Attrs]);
accounting_attrs([{port_type, pppoe_vlan}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?NAS_Port_Type, 33}|Attrs]);
accounting_attrs([{port_type, pppoe_qinq}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?NAS_Port_Type, 34}|Attrs]);

%% DSL-Forum PPPoE Intermediate Agent Attributes
accounting_attrs([{'ADSL-Agent-Circuit-Id', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?ADSL_Agent_Circuit_Id, Value}|Attrs]);
accounting_attrs([{'ADSL-Agent-Remote-Id', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?ADSL_Agent_Remote_Id, Value}|Attrs]);
accounting_attrs([{'Actual-Data-Rate-Upstream', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Actual_Data_Rate_Upstream, Value}|Attrs]);
accounting_attrs([{'Actual-Data-Rate-Downstream', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Actual_Data_Rate_Downstream, Value}|Attrs]);
accounting_attrs([{'Minimum-Data-Rate-Upstream', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Minimum_Data_Rate_Upstream, Value}|Attrs]);
accounting_attrs([{'Minimum-Data-Rate-Downstream', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Minimum_Data_Rate_Downstream, Value}|Attrs]);
accounting_attrs([{'Attainable-Data-Rate-Upstream', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Attainable_Data_Rate_Upstream, Value}|Attrs]);
accounting_attrs([{'Attainable-Data-Rate-Downstream', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Attainable_Data_Rate_Downstream, Value}|Attrs]);
accounting_attrs([{'Maximum-Data-Rate-Upstream', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Maximum_Data_Rate_Upstream, Value}|Attrs]);
accounting_attrs([{'Maximum-Data-Rate-Downstream', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Maximum_Data_Rate_Downstream, Value}|Attrs]);
accounting_attrs([{'Minimum-Data-Rate-Upstream-Low-Power', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Minimum_Data_Rate_Upstream_Low_Power, Value}|Attrs]);
accounting_attrs([{'Minimum-Data-Rate-Downstream-Low-Power', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Minimum_Data_Rate_Downstream_Low_Power, Value}|Attrs]);
accounting_attrs([{'Maximum-Interleaving-Delay-Upstream', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Maximum_Interleaving_Delay_Upstream, Value}|Attrs]);
accounting_attrs([{'Actual-Interleaving-Delay-Upstream', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Actual_Interleaving_Delay_Upstream, Value}|Attrs]);
accounting_attrs([{'Maximum-Interleaving-Delay-Downstream', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Maximum_Interleaving_Delay_Downstream, Value}|Attrs]);
accounting_attrs([{'Actual-Interleaving-Delay-Downstream', Value}|Rest], Attrs) ->
    accounting_attrs(Rest, [{?Actual_Interleaving_Delay_Downstream, Value}|Attrs]);

accounting_attrs([H|Rest], Attrs) ->
    io:format("unhandled accounting attr: ~p~n", [H]),
    accounting_attrs(Rest, Attrs).

do_accounting_start(#state{config = Config,
			   peerid = PeerId}) ->
    Accounting = proplists:get_value(accounting, Config, []),
    UserName = case proplists:get_value(username, Accounting) of
		   undefined -> PeerId;
		   Value -> Value
	       end,
    {ok, NasId} = application:get_env(nas_identifier),
    {ok, NasIP} = application:get_env(nas_ipaddr),
    Attrs = [
	     {?RStatus_Type, ?RStatus_Type_Start},
	     {?User_Name, UserName},
	     {?Service_Type, 2},
	     {?Framed_Protocol, 1},
	     {?NAS_Identifier, NasId},
	     {?NAS_IP_Address, NasIP}
	     | accounting_attrs(Accounting, [])],
    Req = #radius_request{
	     cmd = accreq,
	     attrs = Attrs,
	     msg_hmac = true},
    {ok, NAS} = application:get_env(radius_acct_server),
    eradius_client:send_request(NAS, Req).

do_accounting_interim(Now, State = #state{config = Config,
					  peerid = PeerId,
					  peer_addrs = Addrs,
					  accounting_start = Start}) ->
    io:format("do_accounting_interim~n"),
    Accounting = proplists:get_value(accounting, Config, []),
    UserName = case proplists:get_value(username, Accounting) of
		   undefined -> PeerId;
		   Value -> Value
	       end,
    HisAddr = proplists:get_value(ipcp, Addrs),
    io:format("HisAddr: ~p~n", [HisAddr]),
    Counter = transport_get_acc_counter(State, HisAddr),
    {ok, NasId} = application:get_env(nas_identifier),
    {ok, NasIP} = application:get_env(nas_ipaddr),
    Attrs = [
	     {?RStatus_Type, ?RStatus_Type_Update},
	     {?User_Name, UserName},
	     {?Service_Type, 2},
	     {?Framed_Protocol, 1},
	     {?NAS_Identifier, NasId},
	     {?NAS_IP_Address, NasIP},
	     {?RSession_Time, round((Now - Start) / 10)}
	     | Counter]
	++ accounting_attrs(Accounting, []),
    Req = #radius_request{
	     cmd = accreq,
	     attrs = Attrs,
	     msg_hmac = true},
    {ok, NAS} = application:get_env(radius_acct_server),
    eradius_client:send_request(NAS, Req).

do_accounting_stop(Now, State = #state{config = Config,
				       peerid = PeerId,
				       peer_addrs = Addrs,
				       accounting_start = Start}) ->
    io:format("do_accounting_stop~n"),
    Accounting = proplists:get_value(accounting, Config, []),
    UserName = case proplists:get_value(username, Accounting) of
		   undefined -> PeerId;
		   Value -> Value
	       end,
    HisAddr = proplists:get_value(ipcp, Addrs),
    io:format("HisAddr: ~p~n", [HisAddr]),
    Start0 = if Start =:= undefined -> Now;
		true -> Start
	     end,
    Counter = transport_get_acc_counter(State, HisAddr),
    {ok, NasId} = application:get_env(nas_identifier),
    {ok, NasIP} = application:get_env(nas_ipaddr),
    Attrs = [
	     {?RStatus_Type, ?RStatus_Type_Stop},
	     {?User_Name, UserName},
	     {?Service_Type, 2},
	     {?Framed_Protocol, 1},
	     {?NAS_Identifier, NasId},
	     {?NAS_IP_Address, NasIP},
	     {?RSession_Time, round((Now - Start0) / 10)}
	     | Counter]
	++ accounting_attrs(Accounting, []),
    Req = #radius_request{
	     cmd = accreq,
	     attrs = Attrs,
	     msg_hmac = true},
    {ok, NAS} = application:get_env(radius_acct_server),
    eradius_client:send_request(NAS, Req).

accounting_on() ->
    {ok, NasId} = application:get_env(nas_identifier),
    {ok, NasIP} = application:get_env(nas_ipaddr),
    Attrs = [
	     {?RStatus_Type, ?RStatus_Type_On},
	     {?NAS_Identifier, NasId},
	     {?NAS_IP_Address, NasIP}],
    Req = #radius_request{
	     cmd = accreq,
	     attrs = Attrs,
	     msg_hmac = true},
    {ok, NAS} = application:get_env(radius_acct_server),
    eradius_client:send_request(NAS, Req).

%% get time with 100ms +/50ms presision
now_ticks() ->
    {MegaSecs, Secs, MicroSecs} = erlang:now(),
    MegaSecs * 10000000 + Secs * 10 + round(MicroSecs div 100000).

cancel_timer(undefined) ->
    ok;
cancel_timer(Ref) ->
    gen_fsm:cancel_timer(Ref).
