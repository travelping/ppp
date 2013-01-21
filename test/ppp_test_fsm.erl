-module(ppp_test_fsm).

-behaviour(ppp_fsm).

%% API
-export([start/1, stop/1]).
-export([frame_in/2, lowerup/1, lowerdown/1, loweropen/1, lowerclose/2]).

%% ppp_fsm callbacks
-export([init/2, up/1, down/1, starting/1, finished/1]).
-export([resetci/1, addci/2, ackci/3, nakci/4, rejci/3, reqci/4]).
-export([handler_lower_event/3]).

%-define(debug, 1).
-include("debug.hrl").

-include("../include/ppp_fsm.hrl").

-record(state, {}).

-define(MAX_STATES, 16).

%%%===================================================================
%%% Protocol API
%%%===================================================================

start(Link) ->
    ppp_fsm:start(Link, [], ?MODULE).

stop(Pid) ->
    gen_fsm:sync_send_all_state_event(Pid, {lower, stop}).

lowerup(FSM) ->
    ppp_fsm:fsm_lowerup(FSM).

lowerdown(FSM) ->
    ppp_fsm:fsm_lowerdown(FSM).

loweropen(FSM) ->
    ppp_fsm:fsm_loweropen(FSM).

lowerclose(FSM, Reason) ->
    ppp_fsm:fsm_lowerclose(FSM, Reason).

frame_in(FSM, Frame) ->
    ppp_fsm:fsm_frame_in(FSM, Frame).

%%===================================================================
%% ppp_fsm callbacks
%%===================================================================

%% fsm events

handler_lower_event(stop, {_, _, State}, _) ->
    {stop, normal, ok, State};
handler_lower_event(Event, FSMState, State) ->
    %% do somthing
    ppp_fsm:handler_lower_event(Event, FSMState, State).

init(_, _) ->
    {ok, lcp, #fsm_config{}, #state{}}.

%% fsm callback
resetci(State) ->
    State.

addci(_StateName, State) ->
    {[], State}.

ackci(_StateName, _Options, State) ->
    Reply = true,
    {Reply, State}.

nakci(_StateName, _Options, _TreatAsReject, State) ->
    {true, State}.

rejci(_StateName, _Options, State) ->
    {true, State}.

reqci(_StateName, _Options, _RejectIfDisagree, State) ->
    Verdict = ack,
    {{Verdict, []}, State}.

up(State) ->
    %% Reply = {close, <<"Refused our IP address">>},
    Reply = {up, [], []},
    {Reply, State}.

down(State) ->
    ?DEBUG("~p: Down~n", [?MODULE]),
    {down, State}.

starting(State) ->
    ?DEBUG("~p: Starting~n", [?MODULE]),
    {starting, State}.


finished(State) ->
    ?DEBUG("~p: Finished~n", [?MODULE]),
    {terminated, State}.
