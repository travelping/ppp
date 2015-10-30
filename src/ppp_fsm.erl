%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

-module(ppp_fsm).

-behaviour(gen_fsm).

%% API
-export([start_link/3, start_link/4, start/3, start/4]).
-export([fsm_frame_in/2, fsm_lowerup/1, fsm_lowerdown/1, fsm_loweropen/1, fsm_lowerclose/2]).

-include("ppp_fsm.hrl").

%% gen_fsm callbacks
-export([init/1,
	 initial/2, initial/3,
	 starting/2, starting/3,
	 closed/2, closed/3,
	 stopped/2, stopped/3,
	 closing/2, closing/3,
	 stopping/2, stopping/3,
	 req_sent/2, req_sent/3,
	 ack_rcvd/2, ack_rcvd/3,
	 ack_sent/2, ack_sent/3,
	 opened/2, opened/3,
	 send_event/2,
	 handle_event/3, handle_sync_event/4, handle_info/3,
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
    gen_fsm:sync_send_all_state_event(FSM, {lower, up}).

fsm_lowerdown(undefined) ->
    ok;
fsm_lowerdown(FSM) ->
    gen_fsm:sync_send_all_state_event(FSM, {lower, down}).

fsm_loweropen(FSM) ->
    gen_fsm:sync_send_all_state_event(FSM, {lower, open}).

fsm_lowerclose(undefined, _Reason) ->
    ok;
fsm_lowerclose(FSM, Reason) ->
    gen_fsm:sync_send_all_state_event(FSM, {lower, {close, Reason}}).

fsm_frame_in(FSM, Frame) when is_tuple(Frame) ->
    gen_fsm:sync_send_all_state_event(FSM, Frame).

send_event(FSM, Event) ->
    gen_fsm:send_event(FSM, Event).

%%--------------------------------------------------------------------
start_link(Link, Config, ProtoMod) ->
    gen_fsm:start_link(?MODULE, [Link, Config, ProtoMod], []).
start_link(RegName, Link, Config, ProtoMod) ->
    gen_fsm:start_link(RegName, ?MODULE, [Link, Config, ProtoMod], []).

start(Link, Config, ProtoMod) ->
    gen_fsm:start(?MODULE, [Link, Config, ProtoMod], []).
start(RegName, Link, Config, ProtoMod) ->
    gen_fsm:start(RegName, ?MODULE, [Link, Config, ProtoMod], []).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

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
initial({timeout, _Ref, ?TIMEOUT_MSG}, State) ->
    %% drain spurious timeout
    next_state(initial, State);
initial(Event, State) ->
    proto_cb_event(Event, initial, State).

initial(up, _From, State) ->
    reply(ok, closed, State);
initial(open, _From, State) ->
    {Reply, NewState} = this_layer_starting(State),
    reply(Reply, starting, NewState);
initial({close, _}, _From, State) ->
    reply(ok, initial, State);

initial(Frame, _From, State)
  when ?IS_PROTOCOL_FRAME(Frame, State) ->
    proto_cb_frame(Frame, initial, State);

initial(Event, _From, State) ->
    invalid_event(initial, Event),
    reply({error, invalid}, initial, State).

%% -- starting ---------------------------------------
starting({timeout, _Ref, ?TIMEOUT_MSG}, State) ->
    %% drain spurious timeout
    next_state(starting, State);
starting(Event, State) ->
    proto_cb_event(Event, starting, State).

starting(up, _From, State = #state{config = #fsm_config{silent = true}}) ->
    reply(ok, stopped, State);
starting(up, _From, State = #state{config = #fsm_config{silent = false}}) ->
    NewState0 = initialize_restart_count(State),
    NewState1 = cb_resetci(NewState0),
    NewState2 = send_configure_request(starting, false, NewState1),
    reply(ok, req_sent, NewState2);
starting(open, _From, State) ->
    reply(ok, starting, State);
starting({close, _}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, initial, NewState);

starting(Frame, _From, State)
  when ?IS_PROTOCOL_FRAME(Frame, State) ->
    proto_cb_frame(Frame, starting, State);

starting(Event, _From, State) ->
    invalid_event(starting, Event),
    reply({error, invalid}, starting, State).

%% -- closed -----------------------------------------
closed({timeout, _Ref, ?TIMEOUT_MSG}, State) ->
    %% drain spurious timeout
    next_state(closed, State);
closed(Event, State) ->
    proto_cb_event(Event, closed, State).

closed(down, _From, State) ->
    reply(ok, initial, State);
closed(open, _From, State = #state{config = #fsm_config{silent = true}}) ->
    reply(ok, stopped, State);
closed(open, _From, State = #state{config = #fsm_config{silent = false}}) ->
    NewState0 = initialize_restart_count(State),
    NewState1 = cb_resetci(NewState0),
    NewState3 = send_configure_request(closed, false, NewState1),
    reply(ok, req_sent, NewState3);
closed({close, _}, _From, State) ->
    reply(ok, closed, State);

%% RCR+, RCR-, RCA, RCN
closed({_, Code, Id, _Options}, _From, State)
  when Code == 'CP-Configure-Request';
       Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    %% Go away, we're closed
    NewState = send_terminate_ack(Id, <<>>, State),
    reply(ok, closed, NewState);

%% RTR
closed({_, 'CP-Terminate-Request', Id, _Data}, _From, State) ->
    NewState = send_terminate_ack(Id, <<>>, State),
    reply(ok, closed, NewState);

%% RTA
closed({_, 'CP-Terminate-Ack', _Id, _Data}, _From, State) ->
    reply(ok, closed, State);

%% %% RXJ+
%% closed({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
%%     reply(ok, closed, State);

%% RXJ-
closed({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, closed, NewState);

%% %% RXJ+
%% closed({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
%%     reply(ok, closed, State);

%% RXJ-
closed({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, closed, NewState);

%% RXR
closed({_, 'CP-Discard-Request', _Id}, _From, State) ->
    reply(ok, closed, State);

closed(Frame, _From, State)
  when ?IS_PROTOCOL_FRAME(Frame, State) ->
    proto_cb_frame(Frame, closed, State);

closed(Event, _From, State) ->
    invalid_event(closed, Event),
    reply({error, invalid}, closed, State).

%% -- stopped ----------------------------------------
stopped({timeout, _Ref, ?TIMEOUT_MSG}, State) ->
    %% drain spurious timeout
    next_state(stopped, State);
stopped(Event, State) ->
    proto_cb_event(Event, stopped, State).

stopped(down, _From, State) ->
    {Reply, NewState} = this_layer_starting(State),
    reply(Reply, starting, NewState);
stopped(open, _From, State) ->
%% TODO:
%%   [r]   Restart option; see Open event discussion.
    reply(ok, stopped, State);
stopped({close, _}, _From, State = #state{config = #fsm_config{silent = Silent, passive = Passive}})
  when Silent; Passive ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, closed, NewState);
stopped(close, _From, State) ->
    reply(ok, closed, State);

%% RCR+, RCR-
stopped({_, 'CP-Configure-Request', Id, Options}, _From, State) ->
    NewState0 = initialize_restart_count(State),
    NewState1 = cb_resetci(NewState0),
    NewState2 = send_configure_request(stopped, false, NewState1),
    {Verdict, NewState3} = handle_configure_request(stopped, Id, Options, NewState2),
    case Verdict of
	ack ->
	    reply(ok, ack_sent, NewState3);
	_ ->
	    reply(ok, req_sent, NewState3)
    end;

%% RCA, RCN
stopped({_, Code, Id, _Options}, _From, State)
  when Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    NewState = send_terminate_ack(Id, <<>>, State),
    reply(ok, stopped, NewState);

%% RTR
stopped({_, 'CP-Terminate-Request', Id, _Data}, _From, State) ->
    NewState = send_terminate_ack(Id, <<>>, State),
    reply(ok, stopped, NewState);

%% RTA
stopped({_, 'CP-Terminate-Ack', _Id, _Data}, _From, State) ->
    reply(ok, stopped, State);

%% %% RXJ+
%% stopped({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
%%     reply(ok, stopped, State);

%% RXJ-
stopped({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, stopped, NewState);

%% %% RXJ+
%% stopped({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
%%     reply(ok, stopped, State);

%% RXJ-
stopped({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, stopped, NewState);

%% RXR
stopped({_, 'CP-Discard-Request', _Id}, _From, State) ->
    reply(ok, stopped, State);

stopped(Frame, _From, State)
  when ?IS_PROTOCOL_FRAME(Frame, State) ->
    proto_cb_frame(Frame, stopped, State);

stopped(Event, _From, State) ->
    invalid_event(stopped, Event),
    reply({error, invalid}, stopped, State).

%% -- closing ----------------------------------------
closing({timeout, _Ref, ?TIMEOUT_MSG},
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
closing(Event, State) ->
    proto_cb_event(Event, closing, State).

closing(down, _From, State) ->
    reply(ok, initial, State);
closing(open, _From, State) ->
%% TODO:
%%   [r]   Restart option; see Open event discussion.
    reply(ok, stopping, State);
closing({close, _}, _From, State) ->
    reply(ok, closed, State);

%% RCR+, RCR-, RCA, RCN
closing({_, Code, _Id, _Options}, _From, State)
  when Code == 'CP-Configure-Request';
       Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    reply(ok, closing, State);

%% RTR
closing({_, 'CP-Terminate-Request', Id, _Data}, _From, State) ->
    NewState = send_terminate_ack(Id, <<>>, State),
    reply(ok, closing, NewState);

%% RTA
closing({_, 'CP-Terminate-Ack', _Id, _Data}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, closed, NewState);

%% %% RXJ+
%% closing({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
%%     reply(ok, closing, State);

%% RXJ-
closing({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, closed, NewState);

%% %% RXJ+
%% closing({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
%%     reply(ok, closing, State);

%% RXJ-
closing({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, closed, NewState);

%% RXR
closing({_, 'CP-Discard-Request', _Id}, _From, State) ->
    reply(ok, closing, State);

closing(Frame, _From, State)
  when ?IS_PROTOCOL_FRAME(Frame, State) ->
    proto_cb_frame(Frame, closing, State);

closing(Event, _From, State) ->
    invalid_event(closing, Event),
    reply({error, invalid}, closing, State).

%% -- stopping ---------------------------------------
stopping({timeout, _Ref, ?TIMEOUT_MSG},
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
stopping(Event, State) ->
    proto_cb_event(Event, stopping, State).

stopping(down, _From, State) ->
    reply(ok, starting, State);
stopping(open, _From, State) ->
%% TODO:
%%   [r]   Restart option; see Open event discussion.
    reply(ok, stopping, State);
stopping({close, _}, _From, State) ->
    reply(ok, closing, State);

%% RCR+, RCR-, RCA, RCN
stopping({_, Code, _Id, _Options}, _From, State)
  when Code == 'CP-Configure-Request';
       Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    reply(ok, stopping, State);

%% RTR
stopping({_, 'CP-Terminate-Request', Id, _Data}, _From, State) ->
    NewState = send_terminate_ack(Id, <<>>, State),
    reply(ok, stopping, NewState);

%% RTA
stopping({_, 'CP-Terminate-Ack', _Id, _Data}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, stopped, NewState);

%% %% RXJ+
%% stopping({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
%%     reply(ok, stopping, State);

%% RXJ-
stopping({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, stopped, NewState);

%% %% RXJ+
%% stopping({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
%%     reply(ok, stopping, State);

%% RXJ-
stopping({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, closed, NewState);

%% RXR
stopping({_, 'CP-Discard-Request', _Id}, _From, State) ->
    reply(ok, stopping, State);

stopping(Frame, _From, State)
  when ?IS_PROTOCOL_FRAME(Frame, State) ->
    proto_cb_frame(Frame, stopping, State);

stopping(Event, _From, State) ->
    invalid_event(stopping, Event),
    reply({error, invalid}, stopping, State).

%% -- req_sent ---------------------------------------
req_sent({close, Reason}, State) ->
    NewState = start_terminate_link(Reason, State),
    next_state(closing, NewState);
req_sent({timeout, _Ref, ?TIMEOUT_MSG},
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
req_sent(Event, State) ->
    proto_cb_event(Event, req_sent, State).

req_sent(down, _From, State) ->
    reply(ok, starting, State);
req_sent(open, _From, State) ->
    reply(ok, req_sent, State);
req_sent({close, Reason}, _From, State) ->
    NewState = start_terminate_link(Reason, State),
    reply(ok, closing, NewState);

%% RCR+, RCR-
req_sent({_, 'CP-Configure-Request', Id, Options}, _From, State) ->
    {Verdict, NewState} = handle_configure_request(req_sent, Id, Options, State),
    case Verdict of
	ack ->
	    %% RCR+
	    reply(ok, ack_sent, NewState);
	_ ->
	    %% RCR-
	    reply(ok, req_sent, NewState)
    end;

%% RCA
req_sent({_, 'CP-Configure-Ack', _Id, _Options}, _From, State) ->
    NewState = initialize_restart_count(State),
    reply(ok, ack_rcvd, NewState);

%% RCN
req_sent({_, Code, _Id, _Options}, _From, State)
  when Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    NewState0 = stop_timer(State),
    NewState1 = initialize_restart_count(NewState0),
    NewState2 = send_configure_request(req_sent, false, NewState1),
    reply(ok, req_sent, NewState2);

%% RTR
req_sent({_, 'CP-Terminate-Request', Id, Data}, _From, State) ->
    NewState = send_terminate_ack(Id, Data, State),
    reply(ok, req_sent, NewState);

%% RTA
req_sent({_, 'CP-Terminate-Ack', _Id, _Data}, _From, State) ->
    reply(ok, req_sent, State);

%% %% RXJ+
%% req_sent({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
%%     reply(ok, req_sent, State);

%% RXJ-
req_sent({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, stopped, NewState);

%% %% RXJ+
%% req_sent({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
%%     reply(ok, req_sent, State);

%% RXJ-
req_sent({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, stopped, NewState);

%% RXR
req_sent({_, 'CP-Discard-Request', _Id}, _From, State) ->
    reply(ok, req_sent, State);

req_sent(Frame, _From, State)
  when ?IS_PROTOCOL_FRAME(Frame, State) ->
    proto_cb_frame(Frame, req_sent, State);

req_sent(Event, _From, State) ->
    invalid_event(req_sent, Event),
    reply({error, invalid}, req_sent, State).

%% -- ack_rcvd ---------------------------------------
ack_rcvd({close, Reason}, State) ->
    NewState = start_terminate_link(Reason, State),
    next_state(closing, NewState);
ack_rcvd({timeout, _Ref, ?TIMEOUT_MSG},
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
ack_rcvd(Event, State) ->
    proto_cb_event(Event, ack_rcvd, State).

ack_rcvd(down, _From, State) ->
    reply(ok, starting, State);
ack_rcvd(open, _From, State) ->
    reply(ok, ack_rcvd, State);
ack_rcvd({close, Reason}, _From, State) ->
    NewState = start_terminate_link(Reason, State),
    reply(ok, closing, NewState);

%% RCR+, RCR-
ack_rcvd({_, 'CP-Configure-Request', Id, Options}, _From, State) ->
    {Verdict, NewState0} = handle_configure_request(ack_rcvd, Id, Options, State),
    case Verdict of
	ack ->
	    %% RCR+
	    {Reply, NewState1} = this_layer_up(NewState0),
	    reply(Reply, opened, NewState1);
	_ ->
	    %% RCR-
	    reply(ok, ack_rcvd, NewState0)
    end;

%% RCA, RCN
ack_rcvd({_, Code, _Id, _Options}, _From, State)
  when Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
%% TODO:
%%   [x]   Crossed connection; see RCA event discussion.
    NewState0 = stop_timer(State),
    NewState1 = send_configure_request(ack_rcvd, false, NewState0),
    reply(ok, req_sent, NewState1);

%% RTR
ack_rcvd({_, 'CP-Terminate-Request', Id, Data}, _From, State) ->
    NewState = send_terminate_ack(Id, Data, State),
    reply(ok, req_sent, NewState);

%% RTA
ack_rcvd({_, 'CP-Terminate-Ack', _Id, _Data}, _From, State) ->
    reply(ok, req_sent, State);

%% %% RXJ+
%% ack_rcvd({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
%%     reply(ok, req_sent, State);

%% RXJ-
ack_rcvd({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, stopped, NewState);

%% %% RXJ+
%% ack_rcvd({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
%%     reply(ok, req_sent, State);

%% RXJ-
ack_rcvd({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, stopped, NewState);

%% RXR
ack_rcvd({_, 'CP-Discard-Request', _Id}, _From, State) ->
    reply(ok, ack_rcvd, State);

ack_rcvd(Frame, _From, State)
  when ?IS_PROTOCOL_FRAME(Frame, State) ->
    proto_cb_frame(Frame, ack_rcvd, State);

ack_rcvd(Event, _From, State) ->
    invalid_event(ack_rcvd, Event),
    reply({error, invalid}, ack_rcvd, State).

%% -- ack_sent ---------------------------------------
ack_sent({close, Reason}, State) ->
    NewState = start_terminate_link(Reason, State),
    next_state(closing, NewState);
ack_sent({timeout, _Ref, ?TIMEOUT_MSG},
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
ack_sent(Event, State) ->
    proto_cb_event(Event, ack_sent, State).

ack_sent(down, _From, State) ->
    reply(ok, starting, State);
ack_sent(open, _From, State) ->
    reply(ok, ack_sent, State);
ack_sent({close, Reason}, _From, State) ->
    NewState = start_terminate_link(Reason, State),
    reply(ok, closing, NewState);

%% RCR+, RCR-
ack_sent({_, 'CP-Configure-Request', Id, Options}, _From, State) ->
    {Verdict, NewState0} = handle_configure_request(ack_sent, Id, Options, State),
    case Verdict of
	ack ->
	    %% RCR+
	    reply(ok, ack_sent, NewState0);
	_ ->
	    %% RCR-
	    reply(ok, req_sent, NewState0)
    end;

%% RCA
ack_sent({_, 'CP-Configure-Ack', _Id, _Options}, _From, State) ->
    NewState0 = initialize_restart_count(State),
    {Reply, NewState1} = this_layer_up(NewState0),
    reply(Reply, opened, NewState1);

%% RCN
ack_sent({_, Code, _Id, _Options}, _From, State)
  when Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    NewState0 = stop_timer(State),
    NewState1 = initialize_restart_count(NewState0),
    NewState2 = send_configure_request(ack_sent, false, NewState1),
    reply(ok, ack_sent, NewState2);

%% RTR
ack_sent({_, 'CP-Terminate-Request', Id, Data}, _From, State) ->
    NewState = send_terminate_ack(Id, Data, State),
    reply(ok, req_sent, NewState);

%% RTA
ack_sent({_, 'CP-Terminate-Ack', _Id, _Data}, _From, State) ->
    reply(ok, ack_sent, State);

%% %% RXJ+
%% ack_sent({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
%%     reply(ok, ack_sent, State);

%% RXJ-
ack_sent({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, stopped, NewState);

%% %% RXJ+
%% ack_sent({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
%%     reply(ok, ack_sent, State);

%% RXJ-
ack_sent({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
    {Reply, NewState} = this_layer_finished(State),
    reply(Reply, stopped, NewState);

%% RXR
ack_sent({_, 'CP-Discard-Request', _Id}, _From, State) ->
    reply(ok, ack_sent, State);

ack_sent(Frame, _From, State)
  when ?IS_PROTOCOL_FRAME(Frame, State) ->
    proto_cb_frame(Frame, ack_sent, State);

ack_sent(Event, _From, State) ->
    invalid_event(ack_sent, Event),
    reply({error, invalid}, ack_sent, State).

%% -- opened -----------------------------------------
opened({close, Reason}, State = #state{protocol = Protocol, link = Link}) ->
    ppp_link:layer_down(Link, Protocol, Reason),
    NewState = start_terminate_link(Reason, State),
    next_state(closing, NewState);
opened({timeout, _Ref, ?TIMEOUT_MSG}, State) ->
    %% drain spurious timeout
    next_state(opened, State);
opened(Event, State) ->
    proto_cb_event(Event, opened, State).

opened(down, _From, State) ->
    {Reply, NewState} = this_layer_down(State),
    reply(Reply, starting, NewState);
opened(open, _From, State) ->
%% TODO:
%%   [r]   Restart option; see Open event discussion.
    reply(ok, opened, State);
opened({close, Reason}, _From, State = #state{protocol = Protocol, link = Link}) ->
    ppp_link:layer_down(Link, Protocol, Reason),
    NewState = start_terminate_link(Reason, State),
    reply(ok, closing, NewState);

%% RCR+, RCR-
opened({_, 'CP-Configure-Request', Id, Options}, _From, State) ->
    {Reply, NewState0} = this_layer_down(State),
    NewState1 = cb_resetci(NewState0),
    NewState2 = send_configure_request(opened, false, NewState1),
    {Verdict, NewState3} = handle_configure_request(opened, Id, Options, NewState2),
    case Verdict of
	ack ->
	    %% RCR+
	    reply(Reply, ack_sent, NewState3);
	_ ->
	    %% RCR-
	    reply(Reply, req_sent, NewState3)
    end;

%% RCA, RCN
opened({_, Code, _Id, _Options}, _From, State)
  when Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    {Reply, NewState0} = this_layer_down(State),
    NewState1 = cb_resetci(NewState0),
    NewState2 = send_configure_request(opened, false, NewState1),
%% TODO:
%%   [x]   Crossed connection; see RCA event discussion.
    reply(Reply, req_sent, NewState2);

%% RTR
opened({_, 'CP-Terminate-Request', Id, Data}, _From, State) ->
    {Reply, NewState0} = this_layer_down(State),
    NewState1 = zero_restart_count(NewState0),
    NewState2 = send_terminate_ack(Id, Data, NewState1),
    reply(Reply, stopping, NewState2);

%% RTA
opened({_, 'CP-Terminate-Ack', _Id, _Data}, _From, State) ->
    {Reply, NewState0} = this_layer_down(State),
    NewState1 = cb_resetci(NewState0),
    NewState2 = send_configure_request(opened, false, NewState1),
    reply(Reply, req_sent, NewState2);

%% %% RXJ+
%% opened({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
%%     reply(ok, opened, State);

%% RXJ-
opened({_, 'CP-Code-Reject', _Id, _RejectedPacket}, _From, State) ->
    {Reply, NewState0} = this_layer_down(State),
    NewState1 = start_terminate_link(<<>>, NewState0),
    reply(Reply, stopping, NewState1);

%% %% RXJ+
%% opened({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
%%     reply(ok, opened, State);

%% RXJ-
%% opened({_, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, _From, State) ->
%%     {Reply, NewState0} = this_layer_down(State),
%%     NewState1 = start_terminate_link(<<>>, NewState0),
%%     reply(Reply, stopping, NewState1);

%% %% RXJ+
opened({_, 'CP-Protocol-Reject', _Id, RejectedProtocol, _RejectedInfo}, _From, State) ->
    reply({rejected, RejectedProtocol}, opened, State);

%% RXR
opened({_, 'CP-Discard-Request', _Id}, _From, State) ->
    reply(ok, opened, State);

opened(Frame, _From, State)
  when ?IS_PROTOCOL_FRAME(Frame, State) ->
    proto_cb_frame(Frame, opened, State);

opened(Event, _From, State) ->
    invalid_event(opened, Event),
    reply({error, invalid}, opened, State).

%% ---------------------------------------------------
%% special in context callback from protocol module
%%
%% when we get up, down, open or close events,
%% let the protocol module hook them

handler_lower_event(Event, {From, StateName, State}, ProtoState) ->
    io:format("lower ~p in ~p~n", [Event, StateName]),
    NewState = State#state{protocol_state = ProtoState},
    ?MODULE:StateName(Event, From, NewState).

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

handle_event(Event, StateName, State) ->
    io:format("Event: ~p~n", [Event]),
    next_state(StateName, State).

handle_sync_event(Msg = {Protocol, 'CP-Configure-Ack', Id, Options},
	     From, StateName, State = #state{protocol = Protocol}) ->
    case handle_configure_ack(StateName, Id, Options, State) of
	false ->
	    io:format("Ignoring ~p in state ~p~n", [Msg, StateName]),
	    reply(ok, StateName, State);
	NewState ->
	    ?MODULE:StateName(Msg, From, NewState)
    end;

handle_sync_event(Msg = {Protocol, 'CP-Configure-Nak', Id, Options},
	     From, StateName, State = #state{protocol = Protocol}) ->
    case handle_configure_nak(StateName, Id, Options, State) of
	false ->
	    io:format("Ignoring ~p in state ~p~n", [Msg, StateName]),
	    reply(ok, StateName, State);
	NewState ->
	    ?MODULE:StateName(Msg, From, NewState)
    end;

handle_sync_event(Msg = {Protocol, 'CP-Configure-Reject', Id, Options},
	     From, StateName, State = #state{protocol = Protocol}) ->
    case handle_configure_rej(StateName, Id, Options, State) of
	false ->
	    io:format("Ignoring ~p in state ~p~n", [Msg, StateName]),
	    reply(ok, StateName, State);
	NewState ->
	    ?MODULE:StateName(Msg, From, NewState)
    end;

handle_sync_event(Msg, From, StateName, State)
  when ?IS_PROTOCOL_FRAME(Msg, State) andalso ?IS_BASE_CODE(element(2, Msg)) ->
    ?MODULE:StateName(Msg, From, State);

%% RUC
handle_sync_event(Msg, _From, StateName, State)
  when  ?IS_PROTOCOL_FRAME(Msg, State) ->
    proto_cb_frame(Msg, StateName, reject, State);

handle_sync_event({lower, Event}, From, StateName, State) ->
    lower_event(Event, From, StateName, State);

handle_sync_event(Event, _From, StateName, State) ->
    io:format("SyncEvent: ~p~n", [Event]),
    Reply = ok,
    reply(Reply, StateName, State).

handle_info({'EXIT', Link, _Reason}, _StateName, State = #state{link = Link}) ->
    io:format("Link ~p terminated~n", [Link]),
    {stop, normal, State};

handle_info(Info, StateName, State) ->
    io:format("~s: in state ~s, got info: ~p~n", [?MODULE, StateName, Info]),
    next_state(StateName, State).

terminate(_Reason, _StateName, State) ->
    io:format("~s for ~s (~p) terminated~n", [?MODULE, State#state.protocol, self()]),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

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
	    ?MODULE:StateName({close, Reason}, NewState0);
	{stop, Reason, NewProtoState} ->
	    NewState0 = State#state{protocol_state = NewProtoState},
	    {stop, Reason, NewState0};
	 {error, function_clause} ->
	    %% ignore the event
	    next_state(StateName, State)
    end.

proto_cb_frame(Frame, StateName, State) ->
    proto_cb_frame(Frame, StateName, ignore, State).

proto_cb_frame(Frame, StateName, DefaultAction, 
	       State = #state{protocol_mod = ProtoMod, protocol_state = ProtoState}) ->
    case proto_cb(ProtoMod, StateName, [Frame, ProtoState]) of
	{send_reply, NewStateName, Reply, NewProtoState} ->
	    NewState0 = State#state{protocol_state = NewProtoState},
	    NewState1 = send_packet(Reply, NewState0),
	    reply(ok, NewStateName, NewState1);
	{Reply, NewStateName, NewProtoState} ->
	    proto_cb_reply(Reply, Frame, NewStateName,
			   State#state{protocol_state = NewProtoState});
	{error, function_clause} ->
	    proto_cb_reply(DefaultAction, Frame, StateName, State)
    end.

proto_cb_reply(reject, Frame, StateName, State) ->
    NewState = send_code_reject(Frame, State),
    reply(ok, StateName, NewState);
proto_cb_reply(ignore, Frame, StateName, State) ->
    ignore_frame_in(StateName, Frame),
    reply(ok, StateName, State);
proto_cb_reply(Reply, _Frame, StateName, State) ->
    reply(Reply, StateName, State).

lower_event(Event, From, StateName, State = #state{protocol_mod = ProtoMod, protocol_state = ProtoState}) ->
    ProtoMod:handler_lower_event(Event, {From, StateName, State}, ProtoState).

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
    io:format("Sending: ~p~n", [Packet]),
    Data = ppp_frame:encode(Packet),
    link_send(Link, Data),
    State.

ignore_frame_in(StateName, Frame) ->
    io:format("ignoring ~p ~p in state ~p (~p)~n", [element(1, Frame), element(2, Frame), StateName, Frame]).

invalid_event(StateName, Event) ->
    io:format("invalid event ~p in state ~p~n", [Event, StateName]).

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

reply(Reply, NextStateName, State) ->
    io:format("FSM ~p: going to: ~p~n", [State#state.protocol, NextStateName]),
    NewState = state_transitions(NextStateName, State),
    case NextStateName of
	opened ->
	    %% special case, we do not expect any further work soon
	    {reply, Reply, NextStateName, NewState, hibernate};
	_ ->
	    {reply, Reply, NextStateName, NewState}
    end.

next_state(NextStateName, State) ->
    io:format("FSM ~p: going to: ~p~n", [State#state.protocol, NextStateName]),
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
    io:format("Invalid Id: ~p~n", [Id]),
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
    if is_reference(Timer) -> gen_fsm:cancel_timer(Timer);
       true -> ok
    end,
    State#state{timer = gen_fsm:start_timer(Timeout, Msg)}.

stop_timer(State = #state{timer = Timer}) ->
    if is_reference(Timer) -> gen_fsm:cancel_timer(Timer);
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
