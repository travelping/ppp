%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

-module(ppp_link).

-behaviour(gen_statem).

%% API
-export([start_link/4]).
-export([packet_in/2, send/2, link_down/1]).
-export([layer_up/3, layer_down/3, layer_started/3, layer_finished/3]).
-export([auth_withpeer/3, auth_peer/3]).

%% gen_statem callbacks
-export([init/1, callback_mode/0,
	 establish/3, auth/3, network/3, terminating/3,
	 terminate/3, code_change/4]).

-import(ergw_aaa_session, [to_session/1]).

-include_lib("kernel/include/logger.hrl").
-include("ppp.hrl").
-include("ppp_lcp.hrl").
-include("ppp_ipcp.hrl").
-include("ppp_ipv6cp.hrl").

-define(SERVER, ?MODULE).
-define(NETWORK_PROTOCOL_TIMEOUT, 5000).

-record(data, {
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
    gen_statem:cast(Connection, {packet_in, ppplib:frame_decode(Packet)}).

send(Connection, Packet) ->
    gen_statem:cast(Connection, {packet_out, Packet}).

link_down(Connection) ->
    gen_statem:cast(Connection, link_down).

layer_up(Link, Layer, Info) ->
    gen_statem:cast(Link, {layer_up, Layer, Info}).

layer_down(Link, Layer, Info) ->
    gen_statem:cast(Link, {layer_down, Layer, Info}).

layer_started(Link, Layer, Info) ->
    gen_statem:cast(Link, {layer_started, Layer, Info}).

layer_finished(Link, Layer, Info) ->
    gen_statem:cast(Link, {layer_finished, Layer, Info}).

auth_withpeer(Link, Layer, Info) ->
    gen_statem:cast(Link, {auth_withpeer, Layer, Info}).

auth_peer(Link, Layer, Info) ->
    gen_statem:cast(Link, {auth_peer, Layer, Info}).

start_link(TransportModule, TransportPid, TransportRef, Config) ->
    gen_statem:start_link(?MODULE, [{TransportModule, TransportRef}, TransportPid, Config], []).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

callback_mode() ->
    [state_functions, state_enter].

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
    {ok, establish, #data{config = Config, session = Session,
			   transport = TransportPid , transport_info = TransportInfo,
			   lcp = LCP, pap = PAP,
			   nps_required = NPsRequired, nps_open = ordsets:new(),
			   peer_addrs = orddict:new()}}.

establish(enter, _OldStateName, _Data) ->
    keep_state_and_data;

establish(cast, {packet_out, Frame}, Data) ->
    transport_send(Data, Frame),
    keep_state_and_data;

establish(cast, {packet_in, Frame}, Data = #data{lcp = LCP})
  when element(1, Frame) == lcp ->
    ?LOG(debug, "LCP Frame in phase establish: ~p", [Frame]),
    case ppp_lcp:frame_in(LCP, Frame) of
	{up, OurOpts, HisOpts} ->
	    NewData0 = Data#data{our_lcp_opts = OurOpts, his_lcp_opts = HisOpts},
	    lowerup(NewData0),
	    if
		OurOpts#lcp_opts.neg_auth /= [] orelse
		HisOpts#lcp_opts.neg_auth /= [] ->
		    NewData1 = do_auth_peer(OurOpts#lcp_opts.neg_auth, NewData0),
		    NewData2 = do_auth_withpeer(HisOpts#lcp_opts.neg_auth, NewData1),
		    {next_state, auth, NewData2};
		true ->
		    {next_state, network, NewData0}
	    end;
	Reply ->
	    ?LOG(debug, "LCP got: ~p", [Reply]),
	    keep_state_and_data
    end;

establish(cast, {packet_in, Frame}, _Data) ->
    %% RFC 1661, Sect. 3.4:
    %%   Any non-LCP packets received during this phase MUST be silently
    %%   discarded.
    ?LOG(debug, "non-LCP Frame in phase establish: ~p, ignoring", [Frame]),
    keep_state_and_data;

establish(cast, link_down, Data) ->
    lcp_close(<<"Link down">>, Data);

establish(cast, {layer_down, lcp, Reason}, Data) ->
    lowerdown(Data),
    lowerclose(Reason, Data),
    lcp_down(Data);

establish(cast, {layer_finished, lcp, terminated}, Data) ->
    ?LOG(debug, "LCP in phase establish got: terminated"),
    %% TODO: might want to restart LCP.....
    {stop, normal, Data};

establish(info, Info, Data) ->
    handle_info(Info, establish, Data).

auth(enter, _OldStateName, _Data) ->
    keep_state_and_data;

auth(cast, {packet_out, Frame}, Data) ->
    transport_send(Data, Frame),
    keep_state_and_data;

auth(cast, {packet_in, Frame}, Data = #data{lcp = LCP})
  when element(1, Frame) == lcp ->
    ?LOG(debug, "LCP Frame in phase auth: ~p", [Frame]),
    case ppp_lcp:frame_in(LCP, Frame) of
	down ->
	    lcp_down(Data);
	Reply ->
	    ?LOG(debug, "LCP got: ~p", [Reply]),
	    keep_state_and_data
    end;

%% TODO: we might be able to start protocols on demand....
auth(cast, {packet_in, Frame}, Data = #data{pap = PAP})
  when element(1, Frame) == pap ->
    ?LOG(debug, "PAP Frame in phase auth: ~p", [Frame]),
    case ppp_pap:frame_in(PAP, Frame) of
	ok ->
	    keep_state_and_data;
	Reply when is_tuple(Reply) ->
	    ?LOG(debug, "PAP in phase auth got: ~p", [Reply]),
	    auth_reply(Reply, Data)
    end;

auth(cast, {packet_in, Frame}, _Data) ->
    %% RFC 1661, Sect. 3.5:
    %%   Only Link Control Protocol, authentication protocol, and link quality
    %%   monitoring packets are allowed during this phase.  All other packets
    %%   received during this phase MUST be silently discarded.
    ?LOG(debug, "non-Auth Frame: ~p, ignoring", [Frame]),
    keep_state_and_data;

auth(cast, {auth_peer, pap, fail}, Data) ->
    lcp_close(<<"Authentication failed">>, Data);

auth(cast, link_down, Data) ->
    lcp_close(<<"Link down">>, Data);

auth(info, Info, Data) ->
    handle_info(Info, auth, Data).

%% Network Phase Open
network(enter, _OldStateName, Data = #data{config = Config, session = Session}) ->
    NewData2 = accounting_start(init, Data),
    {ok, IPCP} = ppp_ipcp:start_link(self(), Session, Config),
    ppp_ipcp:lowerup(IPCP),
    ppp_ipcp:loweropen(IPCP),
    %% {ok, IPV6CP} = ppp_ipv6cp:start_link(self(), Session, Config),
    %% ppp_ipv6cp:lowerup(IPV6CP),
    %% ppp_ipv6cp:loweropen(IPV6CP),
    IPV6CP = undefined,
    TimeOut = {state_timeout, network_protocol_timeout, ?NETWORK_PROTOCOL_TIMEOUT},
    {keep_state, NewData2#data{ipcp = IPCP, ipv6cp = IPV6CP}, [TimeOut]};

network(cast, session_timeout, Data) ->
    lcp_close(<<"Session Timeout">>, Data);

network(state_timeout, network_protocol_timeout,
	Data = #data{nps_required = NPsRequired, nps_open = NPsOpen}) ->
    case ordsets:is_subset(NPsRequired, NPsOpen) of
	true ->
	    keep_state_and_data;
	_ ->
	    lcp_close(<<"Network Protocols start-up timeout">>, Data)
    end;

network(cast, {packet_out, Frame}, Data) ->
    transport_send(Data, Frame),
    keep_state_and_data;

network(cast, {packet_in, Frame}, Data = #data{lcp = LCP})
  when element(1, Frame) == lcp ->
    ?LOG(debug, "LCP Frame in phase network: ~p", [Frame]),
    case ppp_lcp:frame_in(LCP, Frame) of
	down ->
	    Data1 = accounting_stop(down, Data),
	    lcp_down(Data1);
	{rejected, Protocol}
	  when Protocol == ipcp;
	       Protocol == ipv6cp ->
	    network_protocol_down(Protocol, Data);
	Reply ->
	    ?LOG(debug, "LCP got: ~p", [Reply]),
	    keep_state_and_data
    end;

%% TODO: we might be able to start protocols on demand....
network(cast, {packet_in, Frame}, Data = #data{ipcp = IPCP})
  when element(1, Frame) == ipcp, is_pid(IPCP) ->
    ?LOG(debug, "IPCP Frame in phase network: ~p", [Frame]),
    case ppp_ipcp:frame_in(IPCP, Frame) of
	down ->
	    network_protocol_down(ipcp, Data);
	ok ->
	    keep_state_and_data;
	{up, OurOpts, HisOpts} ->
	    DataNew = network_protocol_up(ipcp, OurOpts, HisOpts, Data),
	    {keep_state, DataNew};
	Reply when is_tuple(Reply) ->
	    ?LOG(debug, "IPCP in phase network got: ~p", [Reply]),
	    keep_state_and_data
    end;

network(cast, {packet_in, Frame}, Data = #data{ipv6cp = IPV6CP})
  when element(1, Frame) == ipv6cp, is_pid(IPV6CP) ->
    ?LOG(debug, "IPV6CP Frame in phase network: ~p", [Frame]),
    case ppp_ipv6cp:frame_in(IPV6CP, Frame) of
	down ->
	    network_protocol_down(ipv6cp, Data);
	ok ->
	    keep_state_and_data;
	{up, OurOpts, HisOpts} ->
	    DataNew = network_protocol_up(ipv6cp, OurOpts, HisOpts, Data),
	    {keep_state, DataNew};
	Reply when is_tuple(Reply) ->
	    ?LOG(debug, "IPV6CP in phase network got: ~p", [Reply]),
	    keep_state_and_data
    end;

network(cast, {packet_in, Frame}, Data) ->
    protocol_reject(Frame, Data),
    keep_state_and_data;

network(cast, link_down, Data) ->
    lcp_close(<<"Link down">>, Data);

network(cast, {layer_down, lcp, Reason}, Data) ->
    Data1 = accounting_stop(down, Data),
    lowerdown(Data1),
    lowerclose(Reason, Data1),
    lcp_down(Data1);

network(info, Info, Data) ->
    handle_info(Info, network, Data).

terminating(enter, _OldStateName, _Data) ->
    keep_state_and_data;

%% drain events
terminating(cast, {auth_peer, pap, fail}, _Data) ->
    keep_state_and_data;
terminating(cast, session_timeout, _Data) ->
    keep_state_and_data;
terminating(cast, network_protocol_timeout, _Data) ->
    keep_state_and_data;

terminating(cast, {packet_out, Frame}, Data) ->
    transport_send(Data, Frame),
    keep_state_and_data;

terminating(cast, {packet_in, Frame}, Data = #data{lcp = LCP})
  when element(1, Frame) == lcp ->
    ?LOG(debug, "LCP Frame in phase terminating: ~p", [Frame]),
    case ppp_lcp:frame_in(LCP, Frame) of
	terminated ->
	    ?LOG(debug, "LCP in phase terminating got: terminated"),
	    %% TODO: might want to restart LCP.....
	    {stop, normal, Data};
	Reply ->
	    ?LOG(debug, "LCP in phase terminating got: ~p", [Reply]),
	    keep_state_and_data
    end;

terminating(cast, {packet_in, Frame}, _Data) ->
    %% RFC 1661, Sect. 3.4:
    %%   Any non-LCP packets received during this phase MUST be silently
    %%   discarded.
    ?LOG(debug, "non-LCP Frame in phase terminating: ~p, ignoring", [Frame]),
    keep_state_and_data;

terminating(cast, link_down, _Data) ->
    keep_state_and_data;

terminating(cast, {layer_down, lcp, Reason}, Data) ->
    Data1 = accounting_stop(down, Data),
    lowerdown(Data1),
    lowerclose(Reason, Data1),
    lcp_down(Data1);

terminating(cast, {layer_finished, lcp, terminated}, Data) ->
    ?LOG(debug, "LCP in phase terminating got: terminated"),
    %% TODO: might want to restart LCP.....
    transport_terminate(Data),
    {stop, normal, Data};

terminating(info, Info, Data) ->
    handle_info(Info, terminating, Data).

handle_info({'EXIT', Transport, _Reason}, _StateName, Data = #data{transport = Transport}) ->
    ?LOG(debug, "Transport ~p terminated", [Transport]),
    Data1 = accounting_stop(down, Data),
    {stop, normal, Data1};

handle_info(Info, StateName, _Data) ->
    ?LOG(debug, "~s: in state ~s, got info: ~p", [?MODULE, StateName, Info]),
    keep_state_and_data.

terminate(_Reason, _StateName, _Data) ->
    ?LOG(debug, "ppp_link ~p terminated", [self()]),
    ok.

code_change(_OldVsn, StateName, Data, _Extra) ->
    {ok, StateName, Data}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

protocol_reject(Request, #data{lcp = LCP}) ->
    ppp_lcp:protocol_reject(LCP, Request).

transport_apply(#data{transport = Transport,
		       transport_info = {TransportModule,
					 TransportRef}}, F, A) ->
    erlang:apply(TransportModule, F, [Transport, TransportRef | A]).

transport_send(Data, Frame) ->
    transport_apply(Data, send, Frame).

transport_terminate(Data) ->
    transport_apply(Data, terminate, []).

transport_get_acc_counter(undefined, _) ->
    [];
transport_get_acc_counter([IP|_], Data) ->
    case transport_apply(Data, get_counter, [IP]) of
	#ppp_stats{packet_count	= {RcvdPkts,  SendPkts},
		   byte_count   = {RcvdBytes, SendBytes}} ->
	    [{'InPackets',  RcvdPkts},
	     {'OutPackets', SendPkts},
	     {'InOctets',   RcvdBytes},
	     {'OutOctets',  SendBytes}];
	_ ->
	    []
    end.

lowerup(#data{pap = PAP, ipcp = IPCP, ipv6cp = IPV6CP}) ->
    ppp_pap:lowerup(PAP),
    ppp_ipcp:lowerup(IPCP),
    ppp_ipv6cp:lowerup(IPV6CP),
    ok.

lowerdown(#data{pap = PAP, ipcp = IPCP, ipv6cp = IPV6CP}) ->
    ppp_pap:lowerdown(PAP),
    ppp_ipcp:lowerdown(IPCP),
    ppp_ipv6cp:lowerdown(IPV6CP),
    ok.

lowerclose(Reason, #data{pap = PAP, ipcp = IPCP, ipv6cp = IPV6CP}) ->
    ppp_pap:lowerclose(PAP, Reason),
    ppp_ipcp:lowerclose(IPCP, Reason),
    ppp_ipv6cp:lowerclose(IPV6CP, Reason),
    ok.

do_auth_peer([], Data) ->
    Data;
do_auth_peer([pap|_], Data = #data{auth_pending = Pending, pap = PAP}) ->
    ppp_pap:auth_peer(PAP),
    Data#data{auth_pending = [auth_peer|Pending]}.

do_auth_withpeer([], Data) ->
    Data;
do_auth_withpeer([pap|_], Data = #data{auth_pending = Pending, pap = PAP}) ->
    ppp_pap:auth_withpeer(PAP, <<"">>, <<"">>),
    Data#data{auth_pending = [auth_withpeer|Pending]}.

auth_success(Direction, Data = #data{auth_pending = Pending}) ->
    NewData = Data#data{auth_pending = proplists:delete(Direction, Pending)},
    if
	NewData#data.auth_pending == [] ->
	    {next_state, network, NewData};
	true ->
	    {next_state, auth, NewData}
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

auth_reply({auth_peer, success, PeerId, Opts}, Data = #data{config = Config}) ->
    Config0 = proplists_merge_recusive(Config, Opts),
    NewData = Data#data{config = Config0, peerid = PeerId},
    auth_success(auth_peer, NewData);

auth_reply({auth_peer, fail}, Data) ->
    lcp_close(<<"Authentication failed">>, Data);

auth_reply({auth_withpeer, success}, Data) ->
    auth_success(auth_withpeer, Data);

auth_reply({auth_withpeer, fail}, Data) ->
    lcp_close(<<"Failed to authenticate ourselves to peer">>, Data).

lcp_down(Data) ->
    NewData = Data#data{our_lcp_opts = undefined, his_lcp_opts = undefined},
    {next_state, terminating, NewData}.

lcp_close(Msg, Data = #data{lcp = LCP}) ->
    Reply = ppp_lcp:lowerclose(LCP, Msg),
    ?LOG(debug, "LCP close got: ~p", [Reply]),
    {next_state, terminating, Data}.

%% Network Phase Finished
%% phase_finished(network, Data) ->
%%     lcp_close(<<"No network protocols running">>, Data).

network_protocol_up(Protocol, OurOpts, HisOpts, Data) ->
    ?LOG(debug, "--------------------------~n~p is UP~n--------------------------", [Protocol]),
    NewData0 = Data#data{nps_open = ordsets:add_element(Protocol, Data#data.nps_open)},
    NewData1 = accounting_init(Protocol, OurOpts, HisOpts, NewData0),
    check_accounting_start(NewData1).

network_protocol_down(Protocol, Data = #data{nps_required = NPsRequired, nps_open = NPsOpen}) ->
    ?LOG(debug, "--------------------------~n~p is DOWN~n--------------------------", [Protocol]),
    NewData = Data#data{nps_open = ordsets:del_element(Protocol, NPsOpen)},
    case ordsets:is_element(Protocol, NPsRequired) of
	true ->
	    %% a required Network Protocol is down, kill the entire link
	    Msg = iolist_to_binary(io_lib:format("network protocol ~p is required, but was rejected", [Protocol])),
	    lcp_close(Msg, NewData);
	_ ->
	    {keep_state, NewData}
    end.

accounting_init(ipcp, _OurOpts,
		_HisOpts = #ipcp_opts{hisaddr = HisAddr},
		Data = #data{session = Session, peer_addrs = Addrs}) ->
    ergw_aaa_session:set(Session, 'Framed-IP-Address', HisAddr),
    NewAddrs = orddict:append(ipcp, HisAddr, Addrs),
    Data#data{peer_addrs = NewAddrs};
accounting_init(ipv6cp,	_OurOpts,
		_HisOpts = #ipv6cp_opts{hisid = HisId},
		Data = #data{session = Session, peer_addrs = Addrs}) ->
    ergw_aaa_session:set(Session, 'Framed-Interface-Id', HisId),
    NewAddrs = orddict:append(ipv6cp, HisId, Addrs),
    Data#data{peer_addrs = NewAddrs}.

%% check wether all required Network Protocol are open, send Accounting Start if so
check_accounting_start(Data = #data{nps_required = NPsRequired,
				      nps_open = NPsOpen,
				      accounting_started = false}) ->
    case ordsets:is_subset(NPsRequired, NPsOpen) of
	true ->
	    accounting_start(network_up, Data);
	_ ->
	    Data
    end;
check_accounting_start(Data) ->
    Data.

accounting_start(init, Data) ->
    Data;
accounting_start(network_up, Data = #data{session = Session}) ->
    ergw_aaa_session:start(Session, #{}),
    Data#data{accounting_started = true}.

accounting_stop(_Reason, Data = #data{session = Session}) ->
    SessionOpts = get_accounting_update(#{}, Data),
    ergw_aaa_session:stop(Session, SessionOpts),
    Data#data{accounting_started = false}.

accounting_update(FSM, SessionOpts) ->
    ?LOG(debug, "accounting_update(~p, ~p)", [FSM, SessionOpts]),
    SessionOpts.

get_accounting_update(SessionOpts, Data = #data{peer_addrs = Addrs}) ->
    ?LOG(debug, "get_accounting_update"),
    HisAddr = proplists:get_value(ipcp, Addrs),
    ?LOG(debug, "HisAddr: ~p", [HisAddr]),
    Counter = transport_get_acc_counter(HisAddr, Data),
    ergw_aaa_session:merge(SessionOpts, to_session(Counter)).
