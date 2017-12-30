%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

-module(ppp_fsm_prop).

-compile(export_all).

-proptest(proper).
-proptest([triq,eqc]).

-ifndef(EQC).
-ifndef(PROPER).
-ifndef(TRIQ).
-define(PROPER,true).
%%-define(EQC,true).
%%-define(TRIQ,true).
-endif.
-endif.
-endif.

-ifdef(EQC).
-include_lib("eqc/include/eqc.hrl").
-define(MOD_eqc,eqc).

-else.
-ifdef(PROPER).
-include_lib("proper/include/proper.hrl").
-define(MOD_eqc,proper).

-else.
-ifdef(TRIQ).
-define(MOD_eqc,triq).
-include_lib("triq/include/triq.hrl").

-endif.
-endif.
-endif.

fsm_prop(_Config) ->
    numtests(1000,
	     ?FORALL(Cmds, proper_fsm:commands(?MODULE),
		     begin
			 {ok, Link} = ppp_test_link:start(),
			 {ok, FSM} = ppp_test_fsm:start(Link),
			 {History, State, Result} =
			     proper_fsm:run_commands(?MODULE, Cmds, [{ppp_fsm, FSM}]),
			 catch ppp_test_fsm:stop(FSM),
			 catch ppp_test_link:stop(Link),
			 ?WHENFAIL(ct:pal("History: ~w\nState: ~w\nResult: ~p\n",
					  [History, State, Result]),
				   aggregate(zip(proper_fsm:state_names(History),
						 command_names(Cmds)),
					     Result =:= ok))
		     end)).

%%--------------------------------------------------------------------

-record(state, {}).
-define(MUT, ppp_test_fsm).
-define(FSM, {var, ppp_fsm}).

-define(PPP_FSM, [{'Up',       "2",     "irc,scr/6",     "-",         "-",         "-",         "-",         "-",         "-",         "-",           "-"},
		  {'Down',     "-",         "-",         "0",       "tls/1",       "0",         "1",         "1",         "1",         "1",         "tld/1"},
		  {'Open',   "tls/1",       "1",     "irc,scr/6",     "3r",        "5r",        "5r",        "6",         "7",         "8",           "9r"},
		  {'Close',    "0",         "0",         "2",         "2",         "4",         "4",     "irc,str/4", "irc,str/4", "irc,str/4", "tld,irc,str/4"},
		  %% {'TO+',      "-",         "-",         "-",         "-",       "str/4",     "str/5",     "scr/6",     "scr/6",     "scr/8",         "-"},
		  %% {'TO-',      "-",         "-",         "-",         "-",       "tlf/2",     "tlf/3",     "tlf/3p",    "tlf/3p",    "tlf/3p",        "-"},
		  {'RCR+',     "-",         "-",       "sta/2", "irc,scr,sca/8",   "4",         "5",       "sca/8",   "sca,tlu/9",   "sca/8",   "tld,scr,sca/8"},
		  {'RCR-',     "-",         "-",       "sta/2", "irc,scr,scn/6",   "4",         "5",       "scn/6",     "scn/7",     "scn/6",   "tld,scr,scn/6"},
		  {'RCA',      "-",         "-",       "sta/2",     "sta/3",       "4",         "5",       "irc/7",     "scr/6x",  "irc,tlu/9",   "tld,scr/6x"},
		  {'RCN',      "-",         "-",       "sta/2",     "sta/3",       "4",         "5",     "irc,scr/6",   "scr/6x",  "irc,scr/8",   "tld,scr/6x"},
		  {'RTR',      "-",         "-",       "sta/2",     "sta/3",     "sta/4",     "sta/5",     "sta/6",     "sta/6",     "sta/6",   "tld,zrc,sta/5"},
		  {'RTA',      "-",         "-",         "2",         "3",       "tlf/2",     "tlf/3",       "6",         "6",         "8",       "tld,scr/6"},
		  {'RUC',      "-",         "-",       "scj/2",     "scj/3",     "scj/4",     "scj/5",     "scj/6",     "scj/7",     "scj/8",   "tld,scj,scr/6"},
		  {'RXJ+',     "-",         "-",         "2",         "3",         "4",         "5",         "6",         "6",         "8",           "9"},
		  {'RXJ-',     "-",         "-",       "tlf/2",     "tlf/3",     "tlf/2",     "tlf/3",     "tlf/3",     "tlf/3",     "tlf/3",   "tld,irc,str/5"},
		  {'RXR',      "-",         "-",         "2",         "3",         "4",         "5",         "6",         "7",         "8",         "ser/9"}]).
-define(PPP_STATES_LIST, [initial, starting, closed, stopped, closing, stopping, req_sent, ack_rcvd, ack_sent, opened]).
-define(PPP_STATES, {initial, starting, closed, stopped, closing, stopping, req_sent, ack_rcvd, ack_sent, opened}).
-define(PPP_EVENTS, [{'Up',    up_event},    {'Down',  down_event},    {'Open',  open_event}, {'Close', close_event},
                     {'TO+',   to_ok_event}, {'TO-',   to_fail_event}, {'RCR+',  rcr_good},   {'RCR-',  rcr_bad},
                     {'RCA',   rca},         {'RCN',   rcn},           {'RTR',   rtr},        {'RTA',   rta},
                     {'RUC',   ruc},         {'RXJ+',  rxj_good},      {'RXJ-',  rxj_bad},    {'RXR',   rxr}]).

initial_state() -> initial.
initial_state_data() -> #state{}.

up_event(FSM) ->
    ?MUT:lowerup(FSM).

down_event(FSM) ->
    ?MUT:lowerdown(FSM).

open_event(FSM) ->
    ?MUT:loweropen(FSM).

close_event(FSM) ->
    ?MUT:lowerclose(FSM, <<"test done">>).

rcr_good(FSM) ->
    ?MUT:frame_in(FSM, {'CP-Configure-Request', 0, [rcr_good]}).

rcr_bad(FSM) ->
    ?MUT:frame_in(FSM, {'CP-Configure-Request', 0, [rcr_bad]}).

rca(FSM) ->
    ?MUT:frame_in(FSM, {'CP-Configure-Ack', 0, [rca]}).

rcn(FSM) ->
    ?MUT:frame_in(FSM, {'CP-Configure-Nak', 0, [rcn]}).

rtr(FSM) ->
    ?MUT:frame_in(FSM, {'CP-Terminate-Request', 0, [rtr]}).

rta(FSM) ->
    ?MUT:frame_in(FSM, {'CP-Terminate-Ack', 0, [rta]}).

ruc(FSM) ->
    ?MUT:frame_in(FSM, {'Receive-Unknown-Code', 0, [ruc]}).

rxj_good(FSM) ->
    ?MUT:frame_in(FSM, {'CP-Code-Reject', 0, [rxj_good]}).

rxj_bad(FSM) ->
    ?MUT:frame_in(FSM, {'CP-Code-Reject', 0, [rxj_bad]}).

rxr(FSM) ->
    ?MUT:frame_in(FSM, {'CP-Discard-Request',0, [rxr]}).

%% to_ok_event(FSM) ->
%%     ?MUT:frame_in(FSM, {'CP-Discard-Request',0, [rxr]}).

%% to_fail_event(FSM) ->
%%     ?MUT:frame_in(FSM, {'CP-Discard-Request',0, [rxr]}).

%%       | State
%%       |    0         1         2         3         4         5         6         7         8           9
%% Events| Initial   Starting  Closed    Stopped   Closing   Stopping  Req-Sent  Ack-Rcvd  Ack-Sent    Opened
%% ------+-----------------------------------------------------------------------------------------------------
%%  Up   |    2     irc,scr/6     -         -         -         -         -         -         -           -
%%  Down |    -         -         0       tls/1       0         1         1         1         1         tld/1
%%  Open |  tls/1       1     irc,scr/6     3r        5r        5r        6         7         8           9r
%%  Close|    0         0         2         2         4         4     irc,str/4 irc,str/4 irc,str/4 tld,irc,str/4
%%       |
%%   TO+ |    -         -         -         -       str/4     str/5     scr/6     scr/6     scr/8
%%   TO- |    -         -         -         -       tlf/2     tlf/3     tlf/3p    tlf/3p    tlf/3p        -
%%       |
%%  RCR+ |    -         -       sta/2 irc,scr,sca/8   4         5       sca/8   sca,tlu/9   sca/8   tld,scr,sca/8
%%  RCR- |    -         -       sta/2 irc,scr,scn/6   4         5       scn/6     scn/7     scn/6   tld,scr,scn/6
%%  RCA  |    -         -       sta/2     sta/3       4         5       irc/7     scr/6x  irc,tlu/9   tld,scr/6x
%%  RCN  |    -         -       sta/2     sta/3       4         5     irc,scr/6   scr/6x  irc,scr/8   tld,scr/6x
%%       |
%%  RTR  |    -         -       sta/2     sta/3     sta/4     sta/5     sta/6     sta/6     sta/6   tld,zrc,sta/5
%%  RTA  |    -         -         2         3       tlf/2     tlf/3       6         6         8       tld,scr/6
%%       |
%%  RUC  |    -         -       scj/2     scj/3     scj/4     scj/5     scj/6     scj/7     scj/8   tld,scj,scr/6
%%  RXJ+ |    -         -         2         3         4         5         6         6         8           9
%%  RXJ- |    -         -       tlf/2     tlf/3     tlf/2     tlf/3     tlf/3     tlf/3     tlf/3   tld,irc,str/5
%%       |
%%  RXR  |    -         -         2         3         4         5         6         7         8         ser/9

pos(V, [V|_], Cnt) ->
    Cnt;
pos(V, [_|T], Cnt) ->
    pos(V, T, Cnt + 1).

ppp_state(Atom) when is_atom(Atom) ->
    pos(Atom, ?PPP_STATES_LIST, 1);
ppp_state(Num) when is_integer(Num) ->
    element(Num, ?PPP_STATES).

transitions(State, S) ->
    %% find symbolic state
    SymStatePos = ppp_state(State) + 1,
    %% find possible transitions
    Transitions = lists:map(fun(T) -> {element(1, T), element(SymStatePos, T)} end, ?PPP_FSM),
    translate_transition(Transitions, State, S, []).

translate_transition([], _State, _S, Funs) ->
    Funs;
translate_transition([{_, "-"}|T], State, S, Funs) ->
    translate_transition(T, State, S, Funs);
translate_transition([{Event, Trans}|T], State, S, Funs) ->
    {_Actions, NState, _Opt} = dec_state_trans(Trans),
    Fun = proplists:get_value(Event, ?PPP_EVENTS),
    case NState of
	State -> NextState = history;
	_     -> NextState = NState
    end,
    Ev = {NextState, {call, ?MODULE, Fun, [?FSM]}},
    translate_transition(T, State, S, [Ev|Funs]).

initial(S) ->
    transitions(initial, S).
starting(S) ->
    transitions(starting, S).
closed(S) ->
    transitions(closed, S).
stopped(S) ->
    transitions(stopped, S).
closing(S) ->
    transitions(closing, S).
stopping(S) ->
    transitions(stopping, S).
req_sent(S) ->
    transitions(req_sent, S).
ack_rcvd(S) ->
    transitions(ack_rcvd, S).
ack_sent(S) ->
    transitions(ack_sent, S).
opened(S) ->
    transitions(opened, S).

dec_state_trans(Trans) ->
    {Actions, NState} = case string:tokens(Trans, "/") of
			     [A1, A2] -> {A1, A2};
			     _ ->        {[], Trans}
			 end,
    {NextStateNum, Opt} = string:to_integer(NState),
    NextState = ppp_state(NextStateNum + 1),
    {Actions, NextState, Opt}.

precondition(_From, _Target, _StateData, {call,_,_,_}) ->
    true.

postcondition(_From, _Target, _StateData, {call,_,_,_}, _Result) ->
    true.

next_state_data(_From, _Target, StateData, _Result, {call,_,_,_}) ->
    StateData.

weight(initial, _Target, {call,_,lowerup,_}) -> 10;
weight(starting, _Target, {call,_,lowerup,_}) -> 10;
weight(closed, _Target, {call,_,loweropen,_}) -> 10;
weight(_From, _Target, {call,_,frame_in,_}) -> 10;
weight(_From, _Target, {call,_,_,_}) -> 1.
