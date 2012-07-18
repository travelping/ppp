-module(ppp_link).

-behaviour(gen_fsm).

%% API
-export([start_link/2]).
-export([packet_in/2, send/2]).
-export([layer_up/3, layer_down/3, layer_started/3, layer_finished/3]).
-export([auth_withpeer/3, auth_peer/3]).

%% gen_fsm callbacks
-export([init/1,
	 establish/2, auth/2, network/2, terminating/2,
	 handle_event/3, handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).

-include("ppp_lcp.hrl").

-define(SERVER, ?MODULE).

-record(state, {
	  transport		:: pid(), 			%% Transport Layer
	  lcp			:: pid(), 			%% LCP protocol driver
	  pap			:: pid(), 			%% PAP protocol driver
	  ipcp			:: pid(), 			%% IPCP protocol driver

	  auth_required = true	:: boolean,
	  auth_pending = []	:: [atom()],

	  peerid = <<>>		:: binary(),

	  our_lcp_opts		:: #lcp_opts{}, 		%% Options that peer ack'd
	  his_lcp_opts		:: #lcp_opts{}			%% Options that we ack'd
	 }).

%%%===================================================================
%%% API
%%%===================================================================

packet_in(Connection, Packet) ->
    gen_fsm:send_event(Connection, {packet_in, ppp_frame:decode(Packet)}).

send(Connection, Packet) ->
    gen_fsm:send_all_state_event(Connection, {packet_out, Packet}).

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

start_link(TransportModule, TransportRef) ->
    gen_fsm:start_link(?MODULE, [{TransportModule, TransportRef}], []).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

init([Transport]) ->
    process_flag(trap_exit, true),
    Config = [
	      silent,
	      {ipcp_hisaddr, <<10,0,0,2>>},
	      {ipcp_ouraddr, <<10,0,0,1>>},
	      {ms_dns, <<10,0,0,1>>}
	     ],

    {ok, LCP} = ppp_lcp:start_link(self(), Config),
    {ok, PAP} = ppp_pap:start_link(self(), Config),
    {ok, IPCP} = ppp_ipcp:start_link(self(), Config),
    ppp_lcp:loweropen(LCP),
    ppp_lcp:lowerup(LCP),
    {ok, establish, #state{transport = Transport, lcp = LCP, pap = PAP, ipcp = IPCP}}.

establish({packet_in, Frame}, State = #state{lcp = LCP})
  when element(1, Frame) == lcp ->
    io:format("LCP Frame: ~p~n", [Frame]),
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
		    loweropen(NewState0),
		    {next_state, network, NewState0}
	    end;
	Reply ->
	    io:format("LCP got: ~p~n", [Reply]),
	    {next_state, establish, State}
    end;

establish({packet_in, Frame}, State) ->
    io:format("non-LCP Frame: ~p, ignoring~n", [Frame]),
    {next_state, establish, State}.

auth({packet_in, Frame}, State = #state{lcp = LCP})
  when element(1, Frame) == lcp ->
    io:format("LCP Frame: ~p~n", [Frame]),
    case ppp_lcp:frame_in(LCP, Frame) of
 	down ->
	    NewState = State#state{our_lcp_opts = undefined, his_lcp_opts = undefined},
	    {next_state, terminating, NewState};
	Reply ->
	    io:format("LCP got: ~p~n", [Reply]),
	    {next_state, auth, State}
    end;

%% TODO: we might be able to start protocols on demand....
auth({packet_in, Frame}, State = #state{pap = PAP})
  when element(1, Frame) == pap ->
    io:format("PAP Frame: ~p~n", [Frame]),
    Reply = ppp_pap:frame_in(PAP, Frame),
    io:format("PAP in phase auth got: ~p~n", [Reply]),
    case Reply of
	ok ->
	    {next_state, auth, State};
	_ when is_tuple(Reply) ->
	    auth_reply(Reply, State)
    end;

auth({packet_in, Frame}, State) ->
    io:format("non-Auth Frame: ~p, ignoring~n", [Frame]),
    {next_state, auth, State}.

%% TODO: we might be able to start protocols on demand....
network({packet_in, Frame}, State = #state{ipcp = IPCP})
  when element(1, Frame) == ipcp ->
    io:format("IPCP Frame: ~p~n", [Frame]),
    Reply = ppp_ipcp:frame_in(IPCP, Frame),
    io:format("IPCP in phase network got: ~p~n", [Reply]),
    case Reply of
	down ->
	    np_finished(State);
	ok ->
	    {next_state, network, State};
	_ when is_tuple(Reply) ->
	    {next_state, network, State}
    end.

terminating({packet_in, Frame}, State = #state{lcp = LCP})
  when element(1, Frame) == lcp ->
    io:format("LCP Frame: ~p~n", [Frame]),
    case ppp_lcp:frame_in(LCP, Frame) of
	terminated ->
	    io:format("LCP in phase terminating got: terminated~n"),
	    %% TODO: might want to restart LCP.....
	    {stop, normal, State};
	Reply ->
	    io:format("LCP in phase terminating got: ~p~n", [Reply]),
	    {next_state, terminating, State}
    end.

handle_event({packet_out, Frame}, StateName, State = #state{transport = Transport}) ->
    transport_send(Transport, Frame),
    {next_state, StateName, State};

handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

handle_sync_event(_Event, _From, StateName, State) ->
    Reply = ok,
    {reply, Reply, StateName, State}.

handle_info(Info, StateName, State) ->
    io:format("Info: ~p~n", [Info]),
    {next_state, StateName, State}.

terminate(_Reason, _StateName, _State) ->
    io:format("ppp_link ~p terminated~n", [self()]),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

transport_send({TransportModule, TransportRef}, Data) ->
    TransportModule:send(TransportRef, Data).

lowerup(#state{pap = PAP, ipcp = IPCP}) ->
    ppp_pap:lowerup(PAP),
    ppp_ipcp:lowerup(IPCP),
    ok.

lowerdown(#state{pap = PAP, ipcp = IPCP}) ->
    ppp_pap:lowerdown(PAP),
    ppp_ipcp:lowerdown(IPCP),
    ok.

loweropen(#state{ipcp = IPCP}) ->
    ppp_ipcp:loweropen(IPCP),
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
	    loweropen(NewState),
	    {next_state, network, NewState};
	true ->
	    {next_state, auth, NewState}
    end.

auth_reply({auth_peer, success, PeerId}, State) ->
    NewState = State#state{peerid = PeerId},
    auth_success(auth_peer, NewState);

auth_reply({auth_peer, fail}, State) ->
    lcp_close(<<"Authentication failed">>, State);
    
auth_reply({auth_withpeer, success}, State) ->
      auth_success(auth_withpeer, State);
  
auth_reply({auth_withpeer, fail}, State) ->
    lcp_close(<<"Failed to authenticate ourselves to peer">>, State).

lcp_close(Msg, State = #state{lcp = LCP}) ->
    Reply = ppp_lcp:lowerclose(LCP, Msg),
    io:format("LCP close got: ~p~n", [Reply]),
    {next_state, terminating, State}.

np_finished(State) ->
    lcp_close(<<"No network protocols running">>, State).
