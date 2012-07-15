-module(ppp_link).

-behaviour(gen_fsm).

%% API
-export([start_link/2]).
-export([packet_in/2, send/2]).
-export([this_layer_up/2, this_layer_down/2, this_layer_started/2, this_layer_finished/2]).

%% gen_fsm callbacks
-export([init/1,
	 establish/2,
	 handle_event/3, handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).

-define(SERVER, ?MODULE).

-record(state, {transport, lcp}).

%%%===================================================================
%%% API
%%%===================================================================

packet_in(Connection, Packet) ->
    gen_fsm:send_event(Connection, {packet_in, ppp_frame:decode(Packet)}).

send(Connection, Packet) ->
    gen_fsm:send_event(Connection, {packet_out, Packet}).

this_layer_up(_Link, _Layer) ->
    ok.

this_layer_down(_Link, _Layer) ->
    ok.

this_layer_started(_Link, _Layer) ->
    ok.

this_layer_finished(_Link, _Layer) ->
    ok.

start_link(TransportModule, TransportRef) ->
    gen_fsm:start_link(?MODULE, [{TransportModule, TransportRef}], []).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

init([Transport]) ->
    process_flag(trap_exit, true),

    {ok, LCP} = ppp_lcp:start_link(self()),
    ppp_lcp:open(LCP),
    ppp_lcp:up(LCP),
    {ok, establish, #state{transport = Transport, lcp = LCP}}.

establish({packet_in, Frame}, State = #state{lcp = LCP})
  when element(1, Frame) == lcp ->
    io:format("LCP Frame: ~p~n", [Frame]),
    ppp_lcp:frame_in(LCP, Frame),
    {next_state, establish, State};

establish({packet_in, Frame}, State) ->
    io:format("non-LCP Frame: ~p, ignoring~n", [Frame]),
    {next_state, establish, State};

establish({packet_out, Frame}, State = #state{transport = Transport}) ->
    transport_send(Transport, Frame),
    {next_state, establish, State}.

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
