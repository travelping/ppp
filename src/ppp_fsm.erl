%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

-module(ppp_fsm).

-behaviour(gen_statem).

%% API
-export([start_link/3, start_link/4, start/3, start/4]).
-export([fsm_frame_in/2, fsm_lowerup/1, fsm_lowerdown/1, fsm_loweropen/1, fsm_lowerclose/2]).

-include("ppp_fsm.hrl").

%% gen_statem callbacks
-export([init/1, callback_mode/0,
	 initial/3,
	 starting/3,
	 closed/3,
	 stopped/3,
	 closing/3,
	 stopping/3,
	 req_sent/3,
	 ack_rcvd/3,
	 ack_sent/3,
	 opened/3,
	 send_event/2,
	 terminate/3, code_change/4]).

%% protocol callbacks
-export([handler_lower_event/3]).

-type protocol_state() :: any().
-type fsm_state() :: initial | starting | closed | stopped
		   | closing | stopping | req_sent | ack_rcvd
		   | ack_sent | opened.

-callback init(Link :: pid(), Config :: list()) ->
    {ok,
     ProtocolTag :: atom(),
     FsmConfig :: #fsm_config{},
     State :: protocol_state()}.

%% Reset our Configuration Information
-callback resetci(State :: protocol_state()) ->
    NewState :: protocol_state().

%% Add our Configuration Information
-callback addci(StateName :: fsm_state(),
		State :: protocol_state()) ->
    {Options :: [ppp_option()],
     NewState :: protocol_state()}.

%% ACK our Configuration Information
-callback ackci(StateName :: fsm_state(),
		Options :: [ppp_option()],
		State :: protocol_state()) ->
    {Reply :: boolean(),
     NewState :: protocol_state()}.

%% NAK our Configuration Information
-callback nakci(StateName :: fsm_state(),
		Options :: [ppp_option()],
		TreatAsReject :: boolean(),
		State :: protocol_state()) ->
    {Reply :: boolean(),
     NewState :: protocol_state()}.

%% Reject our Configuration Information
-callback rejci(StateName :: fsm_state(),
		Options :: [ppp_option()],
		State :: protocol_state()) ->
    {Verdict :: boolean(),
     NewState :: protocol_state()}.

%% Request peer's Configuration Information
-callback reqci(StateName :: fsm_state(),
		Options :: [ppp_option()],
		RejectIfDisagree :: boolean(),
		State :: protocol_state()) ->
    {Reply :: any(),
     ReplyOptions :: [ppp_option()],
     NewState :: protocol_state()}.

%% Called when fsm reaches OPENED state
-callback up(State :: protocol_state()) ->
    {NewState :: protocol_state()}.

%% Called when fsm leaves OPENED state
-callback down(State :: protocol_state()) ->
    {NewState :: protocol_state()}.

%% Called when we want the lower layer up
-callback starting(State :: protocol_state()) ->
    {NewState :: protocol_state()}.

%% Called when we want the lower layer down
-callback finished(State :: protocol_state()) ->
    {NewState :: protocol_state()}.

%% fsm lower event callback
-callback handler_lower_event(Event :: atom(),
			      FSMState :: any(),
			      State :: protocol_state()) ->
    {Reply :: any(),
     NewStateName :: fsm_state(),
     NewState :: any()}.


-define(SERVER, ?MODULE).
-define(TIMEOUT_MSG, ?MODULE).

-record(state, {
	  config			:: #fsm_config{},
	  protocol			:: atom(),

	  protocol_mod			:: atom(),
	  protocol_state		:: any(),

	  link				:: pid(),
	  timer				:: undefined | reference(),
	  reqid = 0			:: integer(),
	  term_restart_count = 0	:: integer(),
	  conf_restart_count = 0	:: integer(),
	  failure_count	= 0		:: integer(),
	  restart_timeout = 0		:: integer(),
	  term_reason			:: undefined | binary(),
	  last_request			:: undefined | 'Terminate-Request' | 'Send-Configure-Request'
	 }).

%%%===================================================================
%%% API
%%%===================================================================

fsm_lowerup(undefined) ->
    ok;
fsm_lowerup(FSM) ->
    gen_statem:call(FSM, {lower, up}).

fsm_lowerdown(undefined) ->
    ok;
fsm_lowerdown(FSM) ->
    gen_statem:call(FSM, {lower, down}).

fsm_loweropen(FSM) ->
    gen_statem:call(FSM, {lower, open}).

fsm_lowerclose(undefined, _Reason) ->
    ok;
fsm_lowerclose(FSM, Reason) ->
    gen_statem:call(FSM, {lower, {close, Reason}}).

fsm_frame_in(FSM, Frame) when is_tuple(Frame) ->
    gen_statem:call(FSM, Frame).

send_event(FSM, Event) ->
    gen_statem:cast(FSM, Event).

%%--------------------------------------------------------------------
start_link(Link, Config, ProtoMod) ->
    gen_statem:start_link(?MODULE, [Link, Config, ProtoMod], []).
start_link(RegName, Link, Config, ProtoMod) ->
    gen_statem:start_link(RegName, ?MODULE, [Link, Config, ProtoMod], []).

start(Link, Config, ProtoMod) ->
    gen_statem:start(?MODULE, [Link, Config, ProtoMod], []).
start(RegName, Link, Config, ProtoMod) ->
    gen_statem:start(RegName, ?MODULE, [Link, Config, ProtoMod], []).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

callback_mode() ->
    state_functions.

init([Link, Config, ProtoMod]) ->
    process_flag(trap_exit, true),

    {ok, Protocol, FsmConfig, ProtoState} = ProtoMod:init(Link, Config),

    State = #state{
      config = FsmConfig,
      protocol = Protocol,

      protocol_mod = ProtoMod,
      protocol_state = ProtoState,

      link = Link
     },

    {ok, initial, State}.

%%===================================================================
%% Events:
%%   Up   = lower layer is Up
%%   Down = lower layer is Down
%%   Open = administrative Open
%%   Close= administrative Close
%%
%%   TO+  = Timeout with counter > 0
%%   TO-  = Timeout with counter expired
%%
%%   RCR+ = Receive-Configure-Request (Good)
%%   RCR- = Receive-Configure-Request (Bad)
%%   RCA  = Receive-Configure-Ack
%%   RCN  = Receive-Configure-Nak/Rej
%%
%%   RTR  = Receive-Terminate-Request
%%   RTA  = Receive-Terminate-Ack
%%
%%   RUC  = Receive-Unknown-Code
%%   RXJ+ = Receive-Code-Reject (permitted)
%%       or Receive-Protocol-Reject
%%   RXJ- = Receive-Code-Reject (catastrophic)
%%       or Receive-Protocol-Reject
%%   RXR  = Receive-Echo-Request
%%       or Receive-Echo-Reply
%%       or Receive-Discard-Request

-define(IS_PROTOCOL_FRAME(Frame, State), (element(1, Frame) == State#state.protocol)).

%% -- initial ----------------------------------------
initial(info, {timeout, _Ref, ?TIMEOUT_MSG}, State) ->
    %% drain spurious timeout
    next_state(initial, State);

initial(info, {'EXIT', _, _} = Info, State) ->
    handle_exit(Info, initial, State);

initial({call, _} = Type, up, State) ->
    reply(Type, ok, closed, State);
initial({call, _} = Type, open, State) ->
    {Reply, NewState} = this_layer_starting(State),
    reply(Type, Reply, starting, NewState);
initial({call, _} = Type, {close, _}, State) ->
    reply(Type, ok, initial, State);

initial(Type, Event, State) ->
    handle_event(Type, Event, initial, State).

%% -- starting ---------------------------------------
starting(info, {timeout, _Ref, ?TIMEOUT_MSG}, State) ->
    %% drain spurious timeout
    next_state(starting, State);

starting(info, {'EXIT', _, _} = Info, State) ->
    handle_exit(Info, starting, State);

starting({call, _} = Type, up, State = #state{config = #fsm_config{silent = true}}) ->
    reply(Type, ok, stopped, State);
starting({call, _} = Type, up, State = #state{config = #fsm_config{silent = false}}) ->
    NewState0 = initialize_restart_count(State),
    NewState1 = cb_resetci(NewState0),
    NewState2 = send_configure_request(starting, false, NewState1),
    reply(Type, ok, req_sent, NewState2);
starting({call, _} = Type, open, State) ->
    reply(Type, ok, starting, State);
starting({call, _} = Type, {close, _}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, initial, NewState);

starting(Type, Event, State) ->
    handle_event(Type, Event, starting, State).

%% -- closed -----------------------------------------
closed(info, {timeout, _Ref, ?TIMEOUT_MSG}, State) ->
    %% drain spurious timeout
    next_state(closed, State);

closed(info, {'EXIT', _, _} = Info, State) ->
    handle_exit(Info, closed, State);

closed({call, _} = Type, down, State) ->
    reply(Type, ok, initial, State);
closed({call, _} = Type, open, State = #state{config = #fsm_config{silent = true}}) ->
    reply(Type, ok, stopped, State);
closed({call, _} = Type, open, State = #state{config = #fsm_config{silent = false}}) ->
    NewState0 = initialize_restart_count(State),
    NewState1 = cb_resetci(NewState0),
    NewState3 = send_configure_request(closed, false, NewState1),
    reply(Type, ok, req_sent, NewState3);
closed({call, _} = Type, {close, _}, State) ->
    reply(Type, ok, closed, State);

%% RCR+, RCR-, RCA, RCN
closed({call, _} = Type, {_, Code, Id, _Options}, State)
  when Code == 'CP-Configure-Request';
       Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    %% Go away, we're closed
    NewState = send_terminate_ack(Id, <<>>, State),
    reply(Type, ok, closed, NewState);

%% RTR
closed({call, _} = Type, {_, 'CP-Terminate-Request', Id, _Data}, State) ->
    NewState = send_terminate_ack(Id, <<>>, State),
    reply(Type, ok, closed, NewState);

%% RTA
closed({call, _} = Type, {_, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    reply(Type, ok, closed, State);

%% %% RXJ+
%% closed({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     reply(Type, ok, closed, State);

%% RXJ-
closed({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, closed, NewState);

%% %% RXJ+
%% closed({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     reply(Type, ok, closed, State);

%% RXJ-
closed({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, closed, NewState);

%% RXR
closed({call, _} = Type, {_, 'CP-Discard-Request', _Id}, State) ->
    reply(Type, ok, closed, State);

closed(Type, Event, State) ->
    handle_event(Type, Event, closed, State).

%% -- stopped ----------------------------------------
stopped(info, {timeout, _Ref, ?TIMEOUT_MSG}, State) ->
    %% drain spurious timeout
    next_state(stopped, State);

stopped(info, {'EXIT', _, _} = Info, State) ->
    handle_exit(Info, stopped, State);

stopped({call, _} = Type, down, State) ->
    {Reply, NewState} = this_layer_starting(State),
    reply(Type, Reply, starting, NewState);
stopped({call, _} = Type, open, State) ->
%% TODO:
%%   [r]   Restart option; see Open event discussion.
    reply(Type, ok, stopped, State);
stopped({call, _} = Type, {close, _}, State = #state{config = #fsm_config{silent = Silent, passive = Passive}})
  when Silent; Passive ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, closed, NewState);
stopped({call, _} = Type, close, State) ->
    reply(Type, ok, closed, State);

%% RCR+, RCR-
stopped({call, _} = Type, {_, 'CP-Configure-Request', Id, Options}, State) ->
    NewState0 = initialize_restart_count(State),
    NewState1 = cb_resetci(NewState0),
    NewState2 = send_configure_request(stopped, false, NewState1),
    {Verdict, NewState3} = handle_configure_request(stopped, Id, Options, NewState2),
    case Verdict of
	ack ->
	    reply(Type, ok, ack_sent, NewState3);
	_ ->
	    reply(Type, ok, req_sent, NewState3)
    end;

%% RCA, RCN
stopped({call, _} = Type, {_, Code, Id, _Options}, State)
  when Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    NewState = send_terminate_ack(Id, <<>>, State),
    reply(Type, ok, stopped, NewState);

%% RTR
stopped({call, _} = Type, {_, 'CP-Terminate-Request', Id, _Data}, State) ->
    NewState = send_terminate_ack(Id, <<>>, State),
    reply(Type, ok, stopped, NewState);

%% RTA
stopped({call, _} = Type, {_, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    reply(Type, ok, stopped, State);

%% %% RXJ+
%% stopped({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     reply(Type, ok, stopped, State);

%% RXJ-
stopped({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, stopped, NewState);

%% %% RXJ+
%% stopped({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     reply(Type, ok, stopped, State);

%% RXJ-
stopped({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, stopped, NewState);

%% RXR
stopped({call, _} = Type, {_, 'CP-Discard-Request', _Id}, State) ->
    reply(Type, ok, stopped, State);

stopped(Type, Event, State) ->
    handle_event(Type, Event, stopped, State).

%% -- closing ----------------------------------------
closing(info, {timeout, _Ref, ?TIMEOUT_MSG},
	State = #state{protocol = Protocol, link = Link, last_request = LastRequest}) ->
    case get_counter(LastRequest, State) of
	Cnt when Cnt > 0 ->
	    NewState = send_terminate_request(State),
	    next_state(closing, NewState);
	0 ->
	    {Reply, NewState} = this_layer_finished(State),
	    ppp_link:layer_finished(Link, Protocol, Reply),
	    next_state(closed, NewState)
    end;

closing(info, {'EXIT', _, _} = Info, State) ->
    handle_exit(Info, closing, State);

closing({call, _} = Type, down, State) ->
    reply(Type, ok, initial, State);
closing({call, _} = Type, open, State) ->
%% TODO:
%%   [r]   Restart option; see Open event discussion.
    reply(Type, ok, stopping, State);
closing({call, _} = Type, {close, _}, State) ->
    reply(Type, ok, closed, State);

%% RCR+, RCR-, RCA, RCN
closing({call, _} = Type, {_, Code, _Id, _Options}, State)
  when Code == 'CP-Configure-Request';
       Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    reply(Type, ok, closing, State);

%% RTR
closing({call, _} = Type, {_, 'CP-Terminate-Request', Id, _Data}, State) ->
    NewState = send_terminate_ack(Id, <<>>, State),
    reply(Type, ok, closing, NewState);

%% RTA
closing({call, _} = Type, {_, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, closed, NewState);

%% %% RXJ+
%% closing({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     reply(Type, ok, closing, State);

%% RXJ-
closing({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, closed, NewState);

%% %% RXJ+
%% closing({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     reply(Type, ok, closing, State);

%% RXJ-
closing({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, closed, NewState);

%% RXR
closing({call, _} = Type, {_, 'CP-Discard-Request', _Id}, State) ->
    reply(Type, ok, closing, State);

closing(Type, Event, State) ->
    handle_event(Type, Event, closing, State).

%% -- stopping ---------------------------------------
stopping(info, {timeout, _Ref, ?TIMEOUT_MSG},
	 State = #state{protocol = Protocol, link = Link, last_request = LastRequest}) ->
    case get_counter(LastRequest, State) of
	Cnt when Cnt > 0 ->
	    NewState = send_terminate_request(State),
	    next_state(stopping, NewState);
	0 ->
	    {Reply, NewState} = this_layer_finished(State),
	    ppp_link:layer_finished(Link, Protocol, Reply),
	    next_state(stopped, NewState)
    end;

stopping(info, {'EXIT', _, _} = Info, State) ->
    handle_exit(Info, stopping, State);

stopping({call, _} = Type, down, State) ->
    reply(Type, ok, starting, State);
stopping({call, _} = Type, open, State) ->
%% TODO:
%%   [r]   Restart option; see Open event discussion.
    reply(Type, ok, stopping, State);
stopping({call, _} = Type, {close, _}, State) ->
    reply(Type, ok, closing, State);

%% RCR+, RCR-, RCA, RCN
stopping({call, _} = Type, {_, Code, _Id, _Options}, State)
  when Code == 'CP-Configure-Request';
       Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    reply(Type, ok, stopping, State);

%% RTR
stopping({call, _} = Type, {_, 'CP-Terminate-Request', Id, _Data}, State) ->
    NewState = send_terminate_ack(Id, <<>>, State),
    reply(Type, ok, stopping, NewState);

%% RTA
stopping({call, _} = Type, {_, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, stopped, NewState);

%% %% RXJ+
%% stopping({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     reply(Type, ok, stopping, State);

%% RXJ-
stopping({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, stopped, NewState);

%% %% RXJ+
%% stopping({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     reply(Type, ok, stopping, State);

%% RXJ-
stopping({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, closed, NewState);

%% RXR
stopping({call, _} = Type, {_, 'CP-Discard-Request', _Id}, State) ->
    reply(Type, ok, stopping, State);

stopping(Type, Event, State) ->
    handle_event(Type, Event, stopping, State).

%% -- req_sent ---------------------------------------
req_sent(internal, {close, Reason}, State) ->
    NewState = start_terminate_link(Reason, State),
    next_state(closing, NewState);

req_sent(info, {timeout, _Ref, ?TIMEOUT_MSG},
	 State = #state{protocol = Protocol, link = Link, last_request = LastRequest}) ->
    case get_counter(LastRequest, State) of
	Cnt when Cnt > 0 ->
	    NewState = send_configure_request(req_sent, true, State),
	    next_state(req_sent, NewState);
	0 ->
	    {Reply, NewState} = this_layer_finished(State),
%% TODO:
%%   [p]   Passive option; see Stopped state discussion.

	    ppp_link:layer_finished(Link, Protocol, Reply),
	    next_state(stopped, NewState)
    end;

req_sent(info, {'EXIT', _, _} = Info, State) ->
    handle_exit(Info, req_sent, State);

req_sent({call, _} = Type, down, State) ->
    reply(Type, ok, starting, State);
req_sent({call, _} = Type, open, State) ->
    reply(Type, ok, req_sent, State);
req_sent({call, _} = Type, {close, Reason}, State) ->
    NewState = start_terminate_link(Reason, State),
    reply(Type, ok, closing, NewState);

%% RCR+, RCR-
req_sent({call, _} = Type, {_, 'CP-Configure-Request', Id, Options}, State) ->
    {Verdict, NewState} = handle_configure_request(req_sent, Id, Options, State),
    case Verdict of
	ack ->
	    %% RCR+
	    reply(Type, ok, ack_sent, NewState);
	_ ->
	    %% RCR-
	    reply(Type, ok, req_sent, NewState)
    end;

%% RCA
req_sent({call, _} = Type, {_, 'CP-Configure-Ack', _Id, _Options}, State) ->
    NewState = initialize_restart_count(State),
    reply(Type, ok, ack_rcvd, NewState);

%% RCN
req_sent({call, _} = Type, {_, Code, _Id, _Options}, State)
  when Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    NewState0 = stop_timer(State),
    NewState1 = initialize_restart_count(NewState0),
    NewState2 = send_configure_request(req_sent, false, NewState1),
    reply(Type, ok, req_sent, NewState2);

%% RTR
req_sent({call, _} = Type, {_, 'CP-Terminate-Request', Id, Data}, State) ->
    NewState = send_terminate_ack(Id, Data, State),
    reply(Type, ok, req_sent, NewState);

%% RTA
req_sent({call, _} = Type, {_, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    reply(Type, ok, req_sent, State);

%% %% RXJ+
%% req_sent({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     reply(Type, ok, req_sent, State);

%% RXJ-
req_sent({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, stopped, NewState);

%% %% RXJ+
%% req_sent({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     reply(Type, ok, req_sent, State);

%% RXJ-
req_sent({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, stopped, NewState);

%% RXR
req_sent({call, _} = Type, {_, 'CP-Discard-Request', _Id}, State) ->
    reply(Type, ok, req_sent, State);

req_sent(Type, Event, State) ->
    handle_event(Type, Event, req_sent, State).

%% -- ack_rcvd ---------------------------------------
ack_rcvd(internal, {close, Reason}, State) ->
    NewState = start_terminate_link(Reason, State),
    next_state(closing, NewState);

ack_rcvd(info, {timeout, _Ref, ?TIMEOUT_MSG},
	 State = #state{protocol = Protocol, link = Link, last_request = LastRequest}) ->
    case get_counter(LastRequest, State) of
	Cnt when Cnt > 0 ->
	    NewState = send_configure_request(ack_rcvd, true, State),
	    next_state(ack_rcvd, NewState);
	0 ->
	    {Reply, NewState} = this_layer_finished(State),
%% TODO:
%%   [p]   Passive option; see Stopped state discussion.

	    ppp_link:layer_finished(Link, Protocol, Reply),
	    next_state(stopped, NewState)
    end;

ack_rcvd(info, {'EXIT', _, _} = Info, State) ->
    handle_exit(Info, ack_rcvd, State);

ack_rcvd({call, _} = Type, down, State) ->
    reply(Type, ok, starting, State);
ack_rcvd({call, _} = Type, open, State) ->
    reply(Type, ok, ack_rcvd, State);
ack_rcvd({call, _} = Type, {close, Reason}, State) ->
    NewState = start_terminate_link(Reason, State),
    reply(Type, ok, closing, NewState);

%% RCR+, RCR-
ack_rcvd({call, _} = Type, {_, 'CP-Configure-Request', Id, Options}, State) ->
    {Verdict, NewState0} = handle_configure_request(ack_rcvd, Id, Options, State),
    case Verdict of
	ack ->
	    %% RCR+
	    {Reply, NewState1} = this_layer_up(NewState0),
	    reply(Type, Reply, opened, NewState1);
	_ ->
	    %% RCR-
	    reply(Type, ok, ack_rcvd, NewState0)
    end;

%% RCA, RCN
ack_rcvd({call, _} = Type, {_, Code, _Id, _Options}, State)
  when Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
%% TODO:
%%   [x]   Crossed connection; see RCA event discussion.
    NewState0 = stop_timer(State),
    NewState1 = send_configure_request(ack_rcvd, false, NewState0),
    reply(Type, ok, req_sent, NewState1);

%% RTR
ack_rcvd({call, _} = Type, {_, 'CP-Terminate-Request', Id, Data}, State) ->
    NewState = send_terminate_ack(Id, Data, State),
    reply(Type, ok, req_sent, NewState);

%% RTA
ack_rcvd({call, _} = Type, {_, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    reply(Type, ok, req_sent, State);

%% %% RXJ+
%% ack_rcvd({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     reply(Type, ok, req_sent, State);

%% RXJ-
ack_rcvd({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, stopped, NewState);

%% %% RXJ+
%% ack_rcvd({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     reply(Type, ok, req_sent, State);

%% RXJ-
ack_rcvd({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, stopped, NewState);

%% RXR
ack_rcvd({call, _} = Type, {_, 'CP-Discard-Request', _Id}, State) ->
    reply(Type, ok, ack_rcvd, State);

ack_rcvd(Type, Event, State) ->
    handle_event(Type, Event, ack_rcvd, State).

%% -- ack_sent ---------------------------------------
ack_sent(internal, {close, Reason}, State) ->
    NewState = start_terminate_link(Reason, State),
    next_state(closing, NewState);

ack_sent(info, {timeout, _Ref, ?TIMEOUT_MSG},
	 State = #state{protocol = Protocol, link = Link, last_request = LastRequest}) ->
    case get_counter(LastRequest, State) of
	Cnt when Cnt > 0 ->
	    NewState = send_configure_request(ack_sent, true, State),
	    next_state(ack_sent, NewState);
	0 ->
	    {Reply, NewState} = this_layer_finished(State),
%% TODO:
%%   [p]   Passive option; see Stopped state discussion.

	    ppp_link:layer_finished(Link, Protocol, Reply),
	    next_state(stopped, NewState)
    end;

ack_sent(info, {'EXIT', _, _} = Info, State) ->
    handle_exit(Info, ack_sent, State);

ack_sent({call, _} = Type, down, State) ->
    reply(Type, ok, starting, State);
ack_sent({call, _} = Type, open, State) ->
    reply(Type, ok, ack_sent, State);
ack_sent({call, _} = Type, {close, Reason}, State) ->
    NewState = start_terminate_link(Reason, State),
    reply(Type, ok, closing, NewState);

%% RCR+, RCR-
ack_sent({call, _} = Type, {_, 'CP-Configure-Request', Id, Options}, State) ->
    {Verdict, NewState0} = handle_configure_request(ack_sent, Id, Options, State),
    case Verdict of
	ack ->
	    %% RCR+
	    reply(Type, ok, ack_sent, NewState0);
	_ ->
	    %% RCR-
	    reply(Type, ok, req_sent, NewState0)
    end;

%% RCA
ack_sent({call, _} = Type, {_, 'CP-Configure-Ack', _Id, _Options}, State) ->
    NewState0 = initialize_restart_count(State),
    {Reply, NewState1} = this_layer_up(NewState0),
    reply(Type, Reply, opened, NewState1);

%% RCN
ack_sent({call, _} = Type, {_, Code, _Id, _Options}, State)
  when Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    NewState0 = stop_timer(State),
    NewState1 = initialize_restart_count(NewState0),
    NewState2 = send_configure_request(ack_sent, false, NewState1),
    reply(Type, ok, ack_sent, NewState2);

%% RTR
ack_sent({call, _} = Type, {_, 'CP-Terminate-Request', Id, Data}, State) ->
    NewState = send_terminate_ack(Id, Data, State),
    reply(Type, ok, req_sent, NewState);

%% RTA
ack_sent({call, _} = Type, {_, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    reply(Type, ok, ack_sent, State);

%% %% RXJ+
%% ack_sent({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     reply(Type, ok, ack_sent, State);

%% RXJ-
ack_sent({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, stopped, NewState);

%% %% RXJ+
%% ack_sent({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     reply(Type, ok, ack_sent, State);

%% RXJ-
ack_sent({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Type, Reply, stopped, NewState);

%% RXR
ack_sent({call, _} = Type, {_, 'CP-Discard-Request', _Id}, State) ->
    reply(Type, ok, ack_sent, State);

ack_sent(Type, Event, State) ->
    handle_event(Type, Event, ack_sent, State).

%% -- opened -----------------------------------------
opened(internal, {close, Reason}, State = #state{protocol = Protocol, link = Link}) ->
    ppp_link:layer_down(Link, Protocol, Reason),
    NewState = start_terminate_link(Reason, State),
    next_state(closing, NewState);

opened(info, {timeout, _Ref, ?TIMEOUT_MSG}, State) ->
    %% drain spurious timeout
    next_state(opened, State);

opened(info, {'EXIT', _, _} = Info, State) ->
    handle_exit(Info, opened, State);

opened({call, _} = Type, down, State) ->
    {Reply, NewState} = this_layer_down(State),
    reply(Type, Reply, starting, NewState);
opened({call, _} = Type, open, State) ->
%% TODO:
%%   [r]   Restart option; see Open event discussion.
    reply(Type, ok, opened, State);
opened({call, _} = Type, {close, Reason}, State = #state{protocol = Protocol, link = Link}) ->
    ppp_link:layer_down(Link, Protocol, Reason),
    NewState = start_terminate_link(Reason, State),
    reply(Type, ok, closing, NewState);

%% RCR+, RCR-
opened({call, _} = Type, {_, 'CP-Configure-Request', Id, Options}, State) ->
    {Reply, NewState0} = this_layer_down(State),
    NewState1 = cb_resetci(NewState0),
    NewState2 = send_configure_request(opened, false, NewState1),
    {Verdict, NewState3} = handle_configure_request(opened, Id, Options, NewState2),
    case Verdict of
	ack ->
	    %% RCR+
	    reply(Type, Reply, ack_sent, NewState3);
	_ ->
	    %% RCR-
	    reply(Type, Reply, req_sent, NewState3)
    end;

%% RCA, RCN
opened({call, _} = Type, {_, Code, _Id, _Options}, State)
  when Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    {Reply, NewState0} = this_layer_down(State),
    NewState1 = cb_resetci(NewState0),
    NewState2 = send_configure_request(opened, false, NewState1),
%% TODO:
%%   [x]   Crossed connection; see RCA event discussion.
    reply(Type, Reply, req_sent, NewState2);

%% RTR
opened({call, _} = Type, {_, 'CP-Terminate-Request', Id, Data}, State) ->
    {Reply, NewState0} = this_layer_down(State),
    NewState1 = zero_restart_count(NewState0),
    NewState2 = send_terminate_ack(Id, Data, NewState1),
    reply(Type, Reply, stopping, NewState2);

%% RTA
opened({call, _} = Type, {_, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    {Reply, NewState0} = this_layer_down(State),
    NewState1 = cb_resetci(NewState0),
    NewState2 = send_configure_request(opened, false, NewState1),
    reply(Type, Reply, req_sent, NewState2);

%% %% RXJ+
%% opened({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     reply(Type, ok, opened, State);

%% RXJ-
opened({call, _} = Type, {_, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    {Reply, NewState0} = this_layer_down(State),
    NewState1 = start_terminate_link(<<>>, NewState0),
    reply(Type, Reply, stopping, NewState1);

%% %% RXJ+
%% opened({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     reply(Type, ok, opened, State);

%% RXJ-
%% opened({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     {Reply, NewState0} = this_layer_down(State),
%%     NewState1 = start_terminate_link(<<>>, NewState0),
%%     reply(Type, Reply, stopping, NewState1);

%% %% RXJ+
opened({call, _} = Type, {_, 'CP-Protocol-Reject', _Id, RejectedProtocol, _RejectedInfo}, State) ->
    reply(Type, {rejected, RejectedProtocol}, opened, State);

%% RXR
opened({call, _} = Type, {_, 'CP-Discard-Request', _Id}, State) ->
    reply(Type, ok, opened, State);

opened(Type, Event, State) ->
    handle_event(Type, Event, opened, State).

%% ---------------------------------------------------
%% special in context callback from protocol module
%%
%% when we get up, down, open or close events,
%% let the protocol module hook them

handler_lower_event(Event, {Type, StateName, State}, ProtoState) ->
    lager:debug("lower ~p in ~p", [Event, StateName]),
    NewState = State#state{protocol_state = ProtoState},
    {next_state, StateName, NewState, {next_event, Type, Event}}.

%% ---------------------------------------------------

%% make code check a bit more readable
-define(IS_BASE_CODE(Code), (Code == 'CP-VendorSpecific' orelse
			     Code == 'CP-Configure-Request' orelse
			     Code == 'CP-Configure-Ack' orelse
			     Code == 'CP-Configure-Nak' orelse
			     Code == 'CP-Configure-Reject' orelse
			     Code == 'CP-Terminate-Request' orelse
			     Code == 'CP-Terminate-Ack' orelse
			     Code == 'CP-Code-Reject' orelse
			     Code == 'CP-Protocol-Reject' orelse
			     Code == 'CP-Echo-Request' orelse
			     Code == 'CP-Echo-Reply' orelse
			     Code == 'CP-Discard-Request' orelse
			     Code == 'CP-Identification' orelse
			     Code == 'CP-Time-Remaining' orelse
			     Code == 'CP-Reset-Request' orelse
			     Code == 'CP-Reset-Reply')).

handle_event(cast, Frame, StateName, State)
  when ?IS_PROTOCOL_FRAME(Frame, State) ->
    proto_cb_frame(cast, Frame, StateName, State);

handle_event({call, _} = Type, Msg = {Protocol, 'CP-Configure-Ack', Id, Options},
	     StateName, State = #state{protocol = Protocol}) ->
    case handle_configure_ack(StateName, Id, Options, State) of
	false ->
	    lager:debug("Ignoring ~p in state ~p", [Msg, StateName]),
	    reply(Type, ok, StateName, State);
	NewState ->
	    {keep_state, NewState, {next_event, Type, Msg}}
    end;

handle_event({call, _} = Type, Msg = {Protocol, 'CP-Configure-Nak', Id, Options},
	     StateName, State = #state{protocol = Protocol}) ->
    case handle_configure_nak(StateName, Id, Options, State) of
	false ->
	    lager:debug("Ignoring ~p in state ~p", [Msg, StateName]),
	    reply(Type, ok, StateName, State);
	NewState ->
	    {keep_state, NewState, {next_event, Type, Msg}}
    end;

handle_event({call, _} = Type, Msg = {Protocol, 'CP-Configure-Reject', Id, Options},
	     StateName, State = #state{protocol = Protocol}) ->
    case handle_configure_rej(StateName, Id, Options, State) of
	false ->
	    lager:debug("Ignoring ~p in state ~p", [Msg, StateName]),
	    reply(Type, ok, StateName, State);
	NewState ->
	    {keep_state, NewState, {next_event, Type, Msg}}
    end;

handle_event(cast, Event, StateName, State) ->
    proto_cb_event(Event, StateName, State);

%% RUC
handle_event(Type, Msg, StateName, State)
  when  ?IS_PROTOCOL_FRAME(Msg, State) ->
    proto_cb_frame(Type, Msg, StateName, reject, State);

handle_event({call, _} = Type, {lower, Event}, StateName, State) ->
    lower_event(Event, Type, StateName, State);

handle_event({call, _} = Type, Event, StateName, State) ->
    invalid_event(StateName, Event),
    reply(Type, {error, invalid}, StateName, State).

handle_exit({'EXIT', Link, _Reason}, _StateName, State = #state{link = Link}) ->
    lager:debug("Link ~p terminated", [Link]),
    {stop, normal, State}.

terminate(_Reason, _StateName, State) ->
    lager:debug("~s for ~s (~p) terminated", [?MODULE, State#state.protocol, self()]),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

cancel_timer(Ref) ->
    case erlang:cancel_timer(Ref) of
	false ->
	    receive {timeout, Ref, _} -> 0
	    after 0 -> false
	    end;
       RemainingTime ->
	    RemainingTime
    end.

%%===================================================================
%% callbacks

proto_cb(Module, Function, Args)
  when is_list(Args) ->
    case erlang:function_exported(Module, Function, length(Args)) of
	true ->
	    try
		apply(Module, Function, Args)
	    catch
		error:function_clause ->
		    {error, function_clause}
	    end;
	_ ->
	    {error, function_clause}
    end.

proto_cb_event(Event, StateName, State = #state{protocol_mod = ProtoMod, protocol_state = ProtoState, reqid = ReqId}) ->
    case proto_cb(ProtoMod, StateName, [Event, ReqId, ProtoState]) of
	{send, Request, NewReqId, NewStateName, NewProtoState} ->
	    NewState0 = State#state{protocol_state = NewProtoState, reqid = NewReqId},
	    NewState1 = send_packet(Request, NewState0),
	    next_state(NewStateName, NewState1);
	{next_state, NewStateName, NewProtoState} ->
	    NewState0 = State#state{protocol_state = NewProtoState},
	    next_state(NewStateName, NewState0);
	{close, Reason, NewProtoState} ->
	    NewState0 = State#state{protocol_state = NewProtoState},
	    {keep_state, NewState0, {next_event, internal, {close, Reason}}};

	{stop, Reason, NewProtoState} ->
	    NewState0 = State#state{protocol_state = NewProtoState},
	    {stop, Reason, NewState0};
	 {error, function_clause} ->
	    %% ignore the event
	    next_state(StateName, State)
    end.

proto_cb_frame(Type, Frame, StateName, State) ->
    proto_cb_frame(Type, Frame, StateName, ignore, State).

proto_cb_frame(Type, Frame, StateName, DefaultAction,
	       State = #state{protocol_mod = ProtoMod, protocol_state = ProtoState}) ->
    case proto_cb(ProtoMod, StateName, [Frame, ProtoState]) of
	{send_reply, NewStateName, Reply, NewProtoState} ->
	    NewState0 = State#state{protocol_state = NewProtoState},
	    NewState1 = send_packet(Reply, NewState0),
	    reply(Type, ok, NewStateName, NewState1);
	{Reply, NewStateName, NewProtoState} ->
	    proto_cb_reply(Type, Reply, Frame, NewStateName,
			   State#state{protocol_state = NewProtoState});
	{error, function_clause} ->
	    proto_cb_reply(Type, DefaultAction, Frame, StateName, State)
    end.

proto_cb_reply(Type, reject, Frame, StateName, State) ->
    NewState = send_code_reject(Frame, State),
    reply(Type, ok, StateName, NewState);
proto_cb_reply(Type, ignore, Frame, StateName, State) ->
    ignore_frame_in(StateName, Frame),
    reply(Type, ok, StateName, State);
proto_cb_reply(Type, Reply, _Frame, StateName, State) ->
    reply(Type, Reply, StateName, State).

lower_event(Event, Type, StateName, State = #state{protocol_mod = ProtoMod, protocol_state = ProtoState}) ->
    ProtoMod:handler_lower_event(Event, {Type, StateName, State}, ProtoState).

callback(Cb, StateName, Args, State = #state{protocol_mod = ProtoMod, protocol_state = ProtoState}) ->
    {Reply, NewProtoState} = apply(ProtoMod, Cb, [StateName] ++ Args ++ [ProtoState]),
    NewState = State#state{protocol_state = NewProtoState},
    {Reply, NewState}.

callback0(Cb, State = #state{protocol_mod = ProtoMod, protocol_state = ProtoState}) ->
    NewProtoState = ProtoMod:Cb(ProtoState),
    State#state{protocol_state = NewProtoState}.

layer_callback0(Cb, State = #state{protocol_mod = ProtoMod, protocol_state = ProtoState}) ->
    {Reply, NewProtoState} = ProtoMod:Cb(ProtoState),
    NewState = State#state{protocol_state = NewProtoState},
    {Reply, NewState}.

cb_up(State) ->
    layer_callback0(up, State).

cb_down(State) ->
    layer_callback0(down, State).

cb_starting(State) ->
    layer_callback0(starting, State).

cb_finished(State) ->
    layer_callback0(finished, State).

cb_resetci(State) ->
    callback0(resetci, State).

cb_addci(StateName, State) ->
    callback(addci, StateName, [], State).

cb_ackci(StateName, Options, State) ->
    callback(ackci, StateName, [Options], State).

cb_nakci(StateName, Options, TreatAsReject, State) ->
    callback(nakci, StateName, [Options, TreatAsReject], State).

cb_rejci(StateName, Options, State) ->
    callback(rejci, StateName, [Options], State).

cb_reqci(StateName, Options, RejectIfDisagree, State) ->
    callback(reqci, StateName, [Options, RejectIfDisagree], State).

%%===================================================================

link_send(Link, Data) ->
    ppp_link:send(Link, Data).

send_packet(Packet, State = #state{link = Link}) ->
    lager:debug("Sending: ~p", [Packet]),
    Data = ppp_frame:encode(Packet),
    link_send(Link, Data),
    State.

ignore_frame_in(StateName, Frame) ->
    lager:debug("ignoring ~p ~p in state ~p (~p)", [element(1, Frame), element(2, Frame), StateName, Frame]).

invalid_event(StateName, Event) ->
    lager:debug("invalid event ~p in state ~p", [Event, StateName]).

-spec get_counter('Terminate-Ack' | 'Terminate-Request' | 'Configure-Request' | 'Configure-Nak', #state{}) -> integer().
get_counter('Terminate-Ack', _State) ->
    0;
get_counter('Terminate-Request', State) ->
    State#state.term_restart_count;
get_counter('Configure-Request', State) ->
    State#state.conf_restart_count;
get_counter('Configure-Nak', State) ->
    State#state.failure_count.

-spec dec_counter('Terminate-Request' | 'Configure-Request' | 'Configure-Nak', #state{}) -> #state{}.
dec_counter('Terminate-Request', State = #state{term_restart_count = Count})
  when Count > 0 ->
    State#state{term_restart_count = Count - 1};
dec_counter('Configure-Request', State = #state{conf_restart_count = Count})
  when Count > 0 ->
    State#state{conf_restart_count = Count - 1};
dec_counter('Configure-Nak', State = #state{failure_count = Count})
  when Count > 0 ->
    State#state{failure_count = Count - 1};
dec_counter(_, State) ->
    State.

state_transitions(NextStateName, State = #state{timer = Timer})
  when is_reference(Timer) andalso
       (NextStateName == initial orelse
	NextStateName == starting orelse
	NextStateName == closed orelse
	NextStateName == stopped orelse
	NextStateName == opened) ->
    stop_timer(State);

state_transitions(_NewStateName, State) ->
    State.

reply(Type, Reply, NextStateName, State) ->
    lager:debug("FSM ~p: going to: ~p", [State#state.protocol, NextStateName]),
    NewState = state_transitions(NextStateName, State),
    Action =
	case Type of
	    {call, From} ->
		[{reply, From, Reply}];
	    _ ->
		[]
	end,
    case NextStateName of
	opened ->
	    %% special case, we do not expect any further work soon
	    {next_state, NextStateName, NewState, [hibernate | Action]};
	_ ->
	    {next_state, NextStateName, NewState, Action}
    end.

next_state(NextStateName, State) ->
    lager:debug("FSM ~p: going to: ~p", [State#state.protocol, NextStateName]),
    NewState = state_transitions(NextStateName, State),
    case NextStateName of
	opened ->
	    %% special case, we do not expect any further work soon
	    {next_state, NextStateName, NewState, hibernate};
	_ ->
	    {next_state, NextStateName, NewState}
    end.

%%===================================================================

%% Event Processor
handle_configure_ack(StateName, Id, Options, State = #state{reqid = Id}) ->
    {Reply, NewState} = cb_ackci(StateName, Options, State),
    case Reply of
	true -> NewState;
	_    -> false
    end;

handle_configure_ack(_, _, _, _) ->
    %% invalid Id -> toss...
    false.

handle_configure_nak(StateName, Id, Options, State = #state{reqid = Id}) ->
    %% TODO: logic..
    TreatAsReject = false,

    {Reply, NewState} = cb_nakci(StateName, Options, TreatAsReject, State),
    case Reply of
	true -> NewState;
	_    -> false
    end;

handle_configure_nak(_, Id, _, _) ->
    %% invalid Id -> toss...
    lager:debug("Invalid Id: ~p", [Id]),
    false.

handle_configure_rej(StateName, Id, Options, State = #state{reqid = Id}) ->
    {Reply, NewState} = cb_rejci(StateName, Options, State),
    case Reply of
	true -> NewState;
	_    -> false
    end;

handle_configure_rej(_, _, _, _) ->
    %% invalid Id -> toss...
    false.

handle_configure_request(StateName, Id, Options, State) ->
    NackCount = get_counter('Configure-Nak', State),
    {{Verdict, ReplyOpts}, NewState0} = cb_reqci(StateName, Options, NackCount == 0, State),
    NewState1 = case Verdict of
		   nack -> 
			send_configure_nak(Id, ReplyOpts, NewState0);
		   ack ->
			send_configure_ack(Id, ReplyOpts, NewState0);
		   rej ->
			send_configure_reject(Id, ReplyOpts, NewState0)
	       end,
    {Verdict, NewState1}.

%%===================================================================
%% FSM Actions:
%%   tlu = This-Layer-Up
%%   tld = This-Layer-Down
%%   tls = This-Layer-Started (aka This-Layer-Starting)
%%   tlf = This-Layer-Finished
%%   irc = Initialize-Restart-Count
%%   zrc = Zero-Restart-Count
%%   scr = Send-Configure-Request
%%   sca = Send-Configure-Ack
%%   scn = Send-Configure-Nak/Rej
%%   str = Send-Terminate-Request
%%   sta = Send-Terminate-Ack
%%   scj = Send-Code-Reject
%%   ser = Send-Echo-Reply

this_layer_up(State) ->
    cb_up(State).

this_layer_down(State) ->
    cb_down(State).

this_layer_starting(State) ->
    cb_starting(State).

this_layer_finished(State) ->
    cb_finished(State).

%% TODO: count and period initial value from config....
initialize_restart_count(State = #state{config = Config}) ->
    State#state{term_restart_count = Config#fsm_config.term_restart_count,
		conf_restart_count = Config#fsm_config.conf_restart_count,
		failure_count = Config#fsm_config.failure_count,
		restart_timeout = Config#fsm_config.restart_timeout
	       }.

%% initialize_failure_count(State = #state{config = Config}) ->
%%     State#state{failure_count = Config#fsm_config.failure_count}.

zero_restart_count(State = #state{config = Config}) ->
    State#state{term_restart_count = 0,
		conf_restart_count = 0,
		failure_count = 0,
		restart_timeout = Config#fsm_config.restart_timeout}.

start_terminate_link(Reason, State) ->
    NewState = initialize_restart_count(State),
    send_terminate_request(NewState#state{term_reason = Reason}).

%%===================================================================

rearm_timer(State) ->
    rearm_timer(?TIMEOUT_MSG, State).
 
rearm_timer(Msg, State = #state{restart_timeout = Timeout}) ->
    rearm_timer(Msg, Timeout, State).

rearm_timer(Msg, Timeout, State = #state{timer = Timer}) ->
    if is_reference(Timer) -> cancel_timer(Timer);
       true -> ok
    end,
    State#state{timer = erlang:start_timer(Timeout, self(), Msg)}.

stop_timer(State = #state{timer = Timer}) ->
    if is_reference(Timer) -> cancel_timer(Timer);
       true -> ok
    end,
    State#state{timer = undefined}.

-spec send_configure_request(StateName :: fsm_state(), Retransmit :: boolean(), State :: #state{}) -> #state{}.
send_configure_request(StateName, Retransmit, State = #state{protocol = Protocol, reqid = Id}) ->
    if Retransmit ->
	    NewId = Id;
       true ->
	    NewId = Id + 1
    end,
    {Options, NewState0} = cb_addci(StateName, State),

    NewState1 = rearm_timer(NewState0),
    NewState2 = NewState1#state{reqid = NewId, last_request = 'Configure-Request'},
    NewState3 = dec_counter('Configure-Request', NewState2),
    send_packet({Protocol, 'CP-Configure-Request', NewId, Options}, NewState3).

send_configure_ack(Id, Options, State = #state{protocol = Protocol}) ->
    send_packet({Protocol, 'CP-Configure-Ack', Id, Options}, State).

send_configure_nak(Id, Options, State = #state{protocol = Protocol}) ->
    NewState = send_packet({Protocol, 'CP-Configure-Nak', Id, Options}, State),
    dec_counter('Configure-Nak', NewState).

send_configure_reject(Id, Options, State = #state{protocol = Protocol}) ->
    send_packet({Protocol, 'CP-Configure-Reject', Id, Options}, State).

send_terminate_request(State = #state{protocol = Protocol, reqid = Id, term_reason = Reason}) ->
    NewState0 = rearm_timer(State),
    NewState1 = NewState0#state{last_request = 'Terminate-Request'},
    NewState2 = dec_counter('Terminate-Request', NewState1),
    send_packet({Protocol, 'CP-Terminate-Request', Id + 1, Reason}, NewState2#state{reqid = Id + 1}).

send_terminate_ack(Id, Data, State = #state{protocol = Protocol}) ->
    NewState0 = rearm_timer(State),
    NewState1 = NewState0#state{last_request = 'Terminate-Ack'},
    send_packet({Protocol, 'CP-Terminate-Ack', Id, Data}, NewState1).

send_code_reject(Request, State = #state{protocol = Protocol}) ->
    send_packet({Protocol, 'CP-Code-Reject', element(3, Request), Request}, State).
