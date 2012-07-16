-module(ppp_link).

-behaviour(gen_fsm).

%% API
-export([start_link/2]).
-export([packet_in/2, send/2]).
-export([layer_up/3, layer_down/3, layer_started/3, layer_finished/3]).
-export([auth_withpeer/3, auth_peer/3]).

%% gen_fsm callbacks
-export([init/1,
	 establish/2, auth/2,
	 handle_event/3, handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).

-include("ppp_lcp.hrl").

-define(SERVER, ?MODULE).

-record(state, {
	  transport		:: pid(), 			%% Transport Layer
	  lcp			:: pid(), 			%% LCP protocol driver
	  pap			:: pid(), 			%% PAP protocol driver

	  auth_required = true	:: boolean,

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

    {ok, LCP} = ppp_lcp:start_link(self(), [silent]),
    {ok, PAP} = ppp_pap:start_link(self(), []),
    ppp_lcp:loweropen(LCP),
    ppp_lcp:lowerup(LCP),
    {ok, establish, #state{transport = Transport, lcp = LCP, pap = PAP}}.

establish({packet_in, Frame}, State = #state{lcp = LCP})
  when element(1, Frame) == lcp ->
    io:format("LCP Frame: ~p~n", [Frame]),
    case ppp_lcp:frame_in(LCP, Frame) of
 	{up, OurOpts, HisOpts} ->
	    NewState0 = State#state{our_lcp_opts = OurOpts, his_lcp_opts = HisOpts},
	    if
		OurOpts#lcp_opts.neg_auth /= [] orelse
		HisOpts#lcp_opts.neg_auth /= [] ->
		    lowerup(auth, NewState0),
		    NewState1 = do_authpeer(OurOpts#lcp_opts.neg_auth, NewState0),
		    NewState2 = do_authwithpeer(HisOpts#lcp_opts.neg_auth, NewState1),
		    {next_state, auth, NewState2};
		true ->
		    lowerup(network, NewState0),
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
	    {next_state, establish, NewState};
	Reply ->
	    io:format("LCP got: ~p~n", [Reply]),
	    {next_state, auth, State}
    end;

%% TODO: we might be able to start protocols on demand....
auth({packet_in, Frame}, State = #state{pap = PAP})
  when element(1, Frame) == pap ->
    io:format("PAP Frame: ~p~n", [Frame]),
    Reply = ppp_pap:frame_in(PAP, Frame),
    io:format("PAP got: ~p~n", [Reply]),
    {next_state, auth, State};

auth({packet_in, Frame}, State) ->
    io:format("non-Auth Frame: ~p, ignoring~n", [Frame]),
    {next_state, auth, State}.

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

lowerup(auth, #state{pap = PAP}) ->
    ppp_pap:lowerup(PAP),
    ok;

lowerup(network, #state{}) ->
    ok.

lowerdown(auth, #state{pap = PAP}) ->
    ppp_pap:lowerdown(PAP),
    ok;
lowerdown(network, #state{}) ->
    ok.

do_authpeer([], State) ->
    State;
do_authpeer([pap|_], State = #state{pap = PAP}) ->
    ppp_pap:authpeer(PAP),
    State.

do_authwithpeer([], State) ->
    State;
do_authwithpeer([pap|_], State = #state{pap = PAP}) ->
    ppp_pap:authwithpeer(PAP, <<"">>, <<"">>),
    State.
