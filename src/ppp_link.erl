%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

-module(ppp_link).

-behaviour(gen_fsm).

%% API
-export([start_link/4]).
-export([packet_in/2, send/2, link_down/1]).
-export([layer_up/3, layer_down/3, layer_started/3, layer_finished/3]).
-export([auth_withpeer/3, auth_peer/3]).

%% gen_fsm callbacks
-export([init/1,
	 establish/2, auth/2, network/2, terminating/2,
	 handle_event/3, handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).

-import(ergw_aaa_session, [to_session/1]).

-include("ppp.hrl").
-include("ppp_lcp.hrl").
-include("ppp_ipcp.hrl").
-include("ppp_ipv6cp.hrl").

-define(SERVER, ?MODULE).
-define(NETWORK_PROTOCOL_TIMEOUT, 5000).

-record(state, {
	  config		:: list(),         		%% config options proplist
	  session		:: ergw_aaa:session(),		%% erGW-AAA session
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

	  accounting_started = false :: boolean			%% has Accounting been started yet?
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

    {ok, NasIP} = application:get_env(nas_ipaddr),

    SessionOpts = #{'Accouting-Update-Fun' => fun accounting_update/2,
		    'Service-Type'         => 'Framed-User',
		    'Framed-Protocol'      => 'PPP',
		    'NAS-IP-Address'       => NasIP},
    {ok, Session} = ergw_aaa_session_sup:new_session(self(), to_session(SessionOpts)),

    NPsRequired = ordsets:from_list([ipcp]),

    {ok, LCP} = ppp_lcp:start_link(self(), Session, Config),
    {ok, PAP} = ppp_pap:start_link(self(), Session, Config),
    ppp_lcp:loweropen(LCP),
    ppp_lcp:lowerup(LCP),
    {ok, establish, #state{config = Config, session = Session,
			   transport = TransportPid , transport_info = TransportInfo,
			   lcp = LCP, pap = PAP,
			   nps_required = NPsRequired, nps_open = ordsets:new(),
			   peer_addrs = orddict:new()}}.

establish({packet_in, Frame}, State = #state{lcp = LCP})
  when element(1, Frame) == lcp ->
    lager:debug("LCP Frame in phase establish: ~p", [Frame]),
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
	    lager:debug("LCP got: ~p", [Reply]),
	    {next_state, establish, State}
    end;

establish({packet_in, Frame}, State) ->
    %% RFC 1661, Sect. 3.4:
    %%   Any non-LCP packets received during this phase MUST be silently
    %%   discarded.
    lager:debug("non-LCP Frame in phase establish: ~p, ignoring", [Frame]),
    {next_state, establish, State};

establish(link_down, State) ->
    lcp_close(<<"Link down">>, State);

establish({layer_down, lcp, Reason}, State) ->
    lowerdown(State),
    lowerclose(Reason, State),
    lcp_down(State);

establish({layer_finished, lcp, terminated}, State) ->
    lager:debug("LCP in phase establish got: terminated"),
    %% TODO: might want to restart LCP.....
    {stop, normal, State}.

auth({packet_in, Frame}, State = #state{lcp = LCP})
  when element(1, Frame) == lcp ->
    lager:debug("LCP Frame in phase auth: ~p", [Frame]),
    case ppp_lcp:frame_in(LCP, Frame) of
 	down ->
	    lcp_down(State);
	Reply ->
	    lager:debug("LCP got: ~p", [Reply]),
	    {next_state, auth, State}
    end;

%% TODO: we might be able to start protocols on demand....
auth({packet_in, Frame}, State = #state{pap = PAP})
  when element(1, Frame) == pap ->
    lager:debug("PAP Frame in phase auth: ~p", [Frame]),
    case ppp_pap:frame_in(PAP, Frame) of
	ok ->
	    {next_state, auth, State};
	Reply when is_tuple(Reply) ->
	    lager:debug("PAP in phase auth got: ~p", [Reply]),
	    auth_reply(Reply, State)
    end;

auth({packet_in, Frame}, State) ->
    %% RFC 1661, Sect. 3.5:
    %%   Only Link Control Protocol, authentication protocol, and link quality
    %%   monitoring packets are allowed during this phase.  All other packets
    %%   received during this phase MUST be silently discarded.
    lager:debug("non-Auth Frame: ~p, ignoring", [Frame]),
    {next_state, auth, State};

auth({auth_peer, pap, fail}, State) ->
    lcp_close(<<"Authentication failed">>, State);

auth(link_down, State) ->
    lcp_close(<<"Link down">>, State).

network(session_timeout, State) ->
    lcp_close(<<"Session Timeout">>, State);

network(network_protocol_timeout, State = #state{nps_required = NPsRequired, nps_open = NPsOpen}) ->
    case ordsets:is_subset(NPsRequired, NPsOpen) of
	true ->
	    {next_state, network, State};
	_ ->
	    lcp_close(<<"Network Protocols start-up timeout">>, State)
    end;

network({packet_in, Frame}, State = #state{lcp = LCP})
  when element(1, Frame) == lcp ->
    lager:debug("LCP Frame in phase network: ~p", [Frame]),
    case ppp_lcp:frame_in(LCP, Frame) of
 	down ->
	    State1 = accounting_stop(down, State),
	    lcp_down(State1);
	{rejected, Protocol}
	  when Protocol == ipcp;
	       Protocol == ipv6cp ->
	    network_protocol_down(Protocol, State);
	Reply ->
	    lager:debug("LCP got: ~p", [Reply]),
	    {next_state, network, State}
    end;

%% TODO: we might be able to start protocols on demand....
network({packet_in, Frame}, State = #state{ipcp = IPCP})
  when element(1, Frame) == ipcp, is_pid(IPCP) ->
    lager:debug("IPCP Frame in phase network: ~p", [Frame]),
    case ppp_ipcp:frame_in(IPCP, Frame) of
	down ->
	    network_protocol_down(ipcp, State);
	ok ->
	    {next_state, network, State};
 	{up, OurOpts, HisOpts} ->
	    network_protocol_up(ipcp, OurOpts, HisOpts, State);
	Reply when is_tuple(Reply) ->
	    lager:debug("IPCP in phase network got: ~p", [Reply]),
	    {next_state, network, State}
    end;

network({packet_in, Frame}, State = #state{ipv6cp = IPV6CP})
  when element(1, Frame) == ipv6cp, is_pid(IPV6CP) ->
    lager:debug("IPV6CP Frame in phase network: ~p", [Frame]),
    case ppp_ipv6cp:frame_in(IPV6CP, Frame) of
	down ->
	    network_protocol_down(ipv6cp, State);
	ok ->
	    {next_state, network, State};
 	{up, OurOpts, HisOpts} ->
	    network_protocol_up(ipv6cp, OurOpts, HisOpts, State);
	Reply when is_tuple(Reply) ->
	    lager:debug("IPV6CP in phase network got: ~p", [Reply]),
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
terminating(session_timeout, State) ->
    {next_state, terminating, State};
terminating(network_protocol_timeout, State) ->
    {next_state, terminating, State};

terminating({packet_in, Frame}, State = #state{lcp = LCP})
  when element(1, Frame) == lcp ->
    lager:debug("LCP Frame in phase terminating: ~p", [Frame]),
    case ppp_lcp:frame_in(LCP, Frame) of
	terminated ->
	    lager:debug("LCP in phase terminating got: terminated"),
	    %% TODO: might want to restart LCP.....
	    {stop, normal, State};
	Reply ->
	    lager:debug("LCP in phase terminating got: ~p", [Reply]),
	    {next_state, terminating, State}
    end;

terminating({packet_in, Frame}, State) ->
    %% RFC 1661, Sect. 3.4:
    %%   Any non-LCP packets received during this phase MUST be silently
    %%   discarded.
    lager:debug("non-LCP Frame in phase terminating: ~p, ignoring", [Frame]),
    {next_state, terminating, State};

terminating(link_down, State) ->
    {next_state, terminating, State};

terminating({layer_down, lcp, Reason}, State) ->
    State1 = accounting_stop(down, State),
    lowerdown(State1),
    lowerclose(Reason, State1),
    lcp_down(State1);

terminating({layer_finished, lcp, terminated}, State) ->
    lager:debug("LCP in phase terminating got: terminated"),
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
    lager:debug("Transport ~p terminated", [Transport]),
    State1 = accounting_stop(down, State),
    {stop, normal, State1};

handle_info(Info, StateName, State) ->
    lager:debug("~s: in state ~s, got info: ~p", [?MODULE, StateName, Info]),
    {next_state, StateName, State}.

terminate(_Reason, _StateName, _State) ->
    lager:debug("ppp_link ~p terminated", [self()]),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

protocol_reject(Request, #state{lcp = LCP}) ->
    ppp_lcp:protocol_reject(LCP, Request).

transport_apply(#state{transport = Transport,
		       transport_info = {TransportModule,
					 TransportRef}}, F, A) ->
    erlang:apply(TransportModule, F, [Transport, TransportRef | A]).

transport_send(State, Data) ->
    transport_apply(State, send, Data).

transport_terminate(State) ->
    transport_apply(State, terminate, []).

transport_get_acc_counter(undefined, _) ->
    [];
transport_get_acc_counter([IP|_], State) ->
    case transport_apply(State, get_counter, [IP]) of
	#ppp_stats{packet_count	= {RcvdPkts,  SendPkts},
		   byte_count   = {RcvdBytes, SendBytes}} ->
	    [{'InPackets',  RcvdPkts},
	     {'OutPackets', SendPkts},
	     {'InOctets',   RcvdBytes},
	     {'OutOctets',  SendBytes}];
	_ ->
	    []
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

proplists_merge_recusive(undefined, L2) when is_list(L2) ->
    L2;
proplists_merge_recusive(L1, L2) when is_list(L1), is_list(L2) ->
    L = lists:foldl(fun({Key, List}, Acc) when is_list(List) ->
			    New = proplists_merge_recusive(proplists:get_value(Key, Acc), List),
			    lists:keystore(Key, 1, Acc, {Key, New});
		       (Opt, Acc) ->
			    lists:keystore(element(1, Opt), 1, Acc, Opt)
		    end,
		    proplists:unfold(L1),
		    proplists:unfold(L2)),
    proplists:compact(L).

auth_reply({auth_peer, success, PeerId, Opts}, State = #state{config = Config}) ->
    Config0 = proplists_merge_recusive(Config, Opts),
    NewState = State#state{config = Config0, peerid = PeerId},
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
    lager:debug("LCP close got: ~p", [Reply]),
    {next_state, terminating, State}.

%% Network Phase Finished
%% phase_finished(network, State) ->
%%     lcp_close(<<"No network protocols running">>, State).

%% Network Phase Open
phase_open(network, State = #state{config = Config, session = Session}) ->
    NewState2 = accounting_start(init, State),
    {ok, IPCP} = ppp_ipcp:start_link(self(), Session, Config),
    ppp_ipcp:lowerup(IPCP),
    ppp_ipcp:loweropen(IPCP),
    %% {ok, IPV6CP} = ppp_ipv6cp:start_link(self(), Session, Config),
    %% ppp_ipv6cp:lowerup(IPV6CP),
    %% ppp_ipv6cp:loweropen(IPV6CP),
    IPV6CP = undefined,
    gen_fsm:send_event_after(?NETWORK_PROTOCOL_TIMEOUT, network_protocol_timeout),
    {next_state, network, NewState2#state{ipcp = IPCP, ipv6cp = IPV6CP}}.

network_protocol_up(Protocol, OurOpts, HisOpts, State) ->
    lager:debug("--------------------------~n~p is UP~n--------------------------", [Protocol]),
    NewState0 = State#state{nps_open = ordsets:add_element(Protocol, State#state.nps_open)},
    NewState1 = accounting_init(Protocol, OurOpts, HisOpts, NewState0),
    NewState2 = check_accounting_start(NewState1),
    {next_state, network, NewState2}.

network_protocol_down(Protocol, State = #state{nps_required = NPsRequired, nps_open = NPsOpen}) ->
    lager:debug("--------------------------~n~p is DOWN~n--------------------------", [Protocol]),
    NewState = State#state{nps_open = ordsets:del_element(Protocol, NPsOpen)},
    case ordsets:is_element(Protocol, NPsRequired) of
	true ->
	    %% a required Network Protocol is down, kill the entire link
	    Msg = iolist_to_binary(io_lib:format("network protocol ~p is required, but was rejected", [Protocol])),
	    lcp_close(Msg, NewState);
	_ ->
	    {next_state, network, NewState}
    end.

accounting_init(ipcp, _OurOpts,
		_HisOpts = #ipcp_opts{hisaddr = HisAddr},
		State = #state{session = Session, peer_addrs = Addrs}) ->
    ergw_aaa_session:set(Session, 'Framed-IP-Address', HisAddr),
    NewAddrs = orddict:append(ipcp, HisAddr, Addrs),
    State#state{peer_addrs = NewAddrs};
accounting_init(ipv6cp,	_OurOpts,
		_HisOpts = #ipv6cp_opts{hisid = HisId},
		State = #state{session = Session, peer_addrs = Addrs}) ->
    ergw_aaa_session:set(Session, 'Framed-Interface-Id', HisId),
    NewAddrs = orddict:append(ipv6cp, HisId, Addrs),
    State#state{peer_addrs = NewAddrs}.

%% check wether all required Network Protocol are open, send Accounting Start if so
check_accounting_start(State = #state{nps_required = NPsRequired,
				      nps_open = NPsOpen,
				      accounting_started = false}) ->
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
accounting_start(network_up, State = #state{session = Session}) ->
    ergw_aaa_session:start(Session, #{}),
    State#state{accounting_started = true}.

accounting_stop(_Reason, State = #state{session = Session}) ->
    SessionOpts = get_accounting_update(#{}, State),
    ergw_aaa_session:stop(Session, SessionOpts),
    State#state{accounting_started = false}.

accounting_update(FSM, SessionOpts) ->
    lager:debug("accounting_update(~p, ~p)", [FSM, SessionOpts]),
    SessionOpts.

get_accounting_update(SessionOpts, State = #state{peer_addrs = Addrs}) ->
    lager:debug("get_accounting_update"),
    HisAddr = proplists:get_value(ipcp, Addrs),
    lager:debug("HisAddr: ~p", [HisAddr]),
    Counter = transport_get_acc_counter(HisAddr, State),
    ergw_aaa_session:merge(SessionOpts, to_session(Counter)).
