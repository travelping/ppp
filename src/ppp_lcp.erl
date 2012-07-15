-module(ppp_lcp).

-behaviour(gen_fsm).

%% API
-export([start_link/1]).
-export([frame_in/2, up/1, down/1, open/1, close/1]).

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
	 handle_event/3, handle_sync_event/4, handle_info/3,
	 terminate/3, code_change/4]).

-define(SERVER, ?MODULE).

-define(MINMRU, 128).
-define(MAXMRU, 1500).
-define(DEFMRU, 1500).
-define(PPP_LQR, 16#c025).
-define(CBCP_OPT, 6).
-define(CHAP_ALL_AUTH, ['MS-CHAP-v2', 'MS-CHAP', sha1, md5]).

-type ppp_option() :: term().

-record(epdisc, {
	  class = 0			:: integer(),
	  address = <<>>		:: binary()
}).

-record(lcp_opts, {
	  neg_mru = false		:: boolean(),			%% Negotiate the MRU?
	  neg_asyncmap = false		:: boolean(),			%% Negotiate the async map?
	  neg_auth = []			:: atom() | [atom()],		%% Ask for UPAP, CHAP (and which MD types (hashing algorithm)) and/or EAP authentication?
	  neg_magicnumber = false	:: boolean(),			%% Ask for magic number?
	  neg_pcompression = false	:: boolean(),			%% HDLC Protocol Field Compression?
	  neg_accompression = false	:: boolean(),			%% HDLC Address/Control Field Compression?
	  neg_lqr = false		:: boolean(),			%% Negotiate use of Link Quality Reports
	  neg_cbcp = false		:: boolean(),			%% Negotiate use of CBCP
	  neg_mrru = false		:: boolean(),			%% negotiate multilink MRRU
	  neg_ssnhf = false		:: boolean(),			%% negotiate short sequence numbers
	  neg_endpoint  = false		:: boolean(),			%% negotiate endpoint discriminator
	  mru = 0			:: integer(),			%% Value of MRU
	  mrru = 0			:: integer(),			%% Value of MRRU, and multilink enable
	  asyncmap = 0			:: integer(),			%% Value of async map
	  magicnumber = 0		:: integer(),
	  numloops = 0			:: integer(),			%% Number of loops during magic number neg.
	  lqr_period = 0		:: integer(),			%% Reporting period for LQR 1/100ths second
	  endpoint = #epdisc{}		:: #epdisc{}			%% endpoint discriminator
}).

-record(state, {
	  config			:: list(),
	  passive = false		:: boolean(),			%% Don't die if we don't get a response
	  silent = true			:: boolean(),			%% Wait for the other end to start first
	  restart = false		:: boolean(),			%% Restart vs. exit after close

	  link				:: pid(),
	  timer				:: undefined | reference(),
	  reqid = 0			:: integer(),
	  term_restart_count = 0	:: integer(),
	  conf_restart_count = 0	:: integer(),
	  failure_count	= 0		:: integer(),
	  restart_timeout = 0		:: integer(),
	  last_request			:: undefined | 'Terminate-Request' | 'Send-Configure-Request',

	  want_opts			:: #lcp_opts{},			%% Options that we want to request
	  got_opts			:: #lcp_opts{}, 		%% Options that peer ack'd
	  allow_opts			:: #lcp_opts{},			%% Options we allow peer to request
	  his_opts			:: #lcp_opts{}			%% Options that we ack'd
	 }).

%%%===================================================================
%%% API
%%%===================================================================

up(LCP) ->
    gen_fsm:sync_send_event(LCP, up).

down(LCP) ->
    gen_fsm:sync_send_event(LCP, down).

open(LCP) ->
    gen_fsm:sync_send_event(LCP, open).

close(LCP) ->
    gen_fsm:sync_send_event(LCP, close).

frame_in(LCP, Frame)
  when element(1, Frame) == lcp ->
    gen_fsm:send_all_state_event(LCP, Frame).

%%--------------------------------------------------------------------
%% @doc
%% Creates a gen_fsm process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this
%% function does not return until Module:init/1 has returned.
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Link) ->
    gen_fsm:start_link(?MODULE, [Link], []).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

init([Link]) ->
    process_flag(trap_exit, true),

    WantOpts = #lcp_opts{
      neg_mru = true,
      mru = ?DEFMRU,
      neg_asyncmap = true,
      neg_magicnumber = true,
      neg_pcompression = true,
      neg_accompression = true
     },

    AllowOpts = #lcp_opts{
      neg_mru = true,
      mru = ?MAXMRU,
      neg_asyncmap = true,
      neg_auth = [eap, {chap, ?CHAP_ALL_AUTH}, pap],
      neg_magicnumber = true,
      neg_pcompression = true,
      neg_accompression = true,
      neg_endpoint = true
     },

%% TODO: apply config to want_opts and allow_opts

    {ok, initial, #state{config = [], link = Link, want_opts = WantOpts, allow_opts = AllowOpts}}.

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

%% -- initial ----------------------------------------
initial(up, _From, State) ->
    reply(ok, closed, State);
initial(open, _From, State) ->
    State1 = this_layer_up(State),
    reply(ok, starting, State1);
initial(close, _From, State) ->
    reply(ok, initial, State);

initial(Event, _From, State) ->
    invalid_event(initial, Event),
    reply({error, invalid}, initial, State).

initial(Frame, State)
  when element(1, Frame) == lcp ->
    ignore_frame_in(initial, Frame),
    next_state(initial, State).

%% -- starting ---------------------------------------
starting(up, _From, State = #state{silent = true}) ->
    reply(ok, stopped, State);
starting(up, _From, State = #state{silent = false}) ->
    NewState0 = initialize_restart_count(State),
    NewState1 = resetci(NewState0),
    NewState2 = send_configure_request(false, NewState1),
    reply(ok, req_sent, NewState2);
starting(open, _From, State) ->
    reply(ok, starting, State);
starting(close, _From, State) ->
    State1 = this_layer_finished(State),
    reply(ok, starting, State1);

starting(Event, _From, State) ->
    invalid_event(starting, Event),
    reply({error, invalid}, starting, State).

starting(Frame, State)
  when element(1, Frame) == lcp ->
    ignore_frame_in(starting, Frame),
    next_state(starting, State).

%% -- closed -----------------------------------------
closed(down, _From, State) ->
    reply(ok, initial, State);
closed(open, _From, State = #state{silent = true}) ->
    reply(ok, stopped, State);
closed(open, _From, State = #state{silent = false}) ->
    NewState0 = initialize_restart_count(State),
    NewState1 = resetci(NewState0),
    NewState3 = send_configure_request(false, NewState1),
    reply(ok, req_sent, NewState3);
closed(close, _From, State) ->
    reply(ok, closed, State);

closed(Event, _From, State) ->
    invalid_event(closed, Event),
    reply({error, invalid}, closed, State).

%% RCR+, RCR-, RCA, RCN
closed({lcp, Code, Id, _Options}, State)
  when Code == 'CP-Configure-Request';
       Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    %% Go away, we're closed
    NewState = send_terminate_ack(Id, <<>>, State),
    next_state(closed, NewState);

%% RTR
closed({lcp, 'CP-Terminate-Request', Id, _Data}, State) ->
    NewState = send_terminate_ack(Id, <<>>, State),
    next_state(closed, NewState);

%% RTA
closed({lcp, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    next_state(closed, State);

%% %% RXJ+
%% closed({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     next_state(closed, State);

%% RXJ-
closed({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    NewState = this_layer_finished(State),
    next_state(closed, NewState);

%% %% RXJ+
%% closed({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     next_state(closed, State);

%% RXJ-
closed({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
    NewState = this_layer_finished(State),
    next_state(closed, NewState);

%% RXR
closed({lcp, 'CP-Discard-Request', _Id}, State) ->
    next_state(closed, State);

%% RUC
closed(Request, State)
  when element(1, Request) == lcp ->
    NewState = send_code_reject(Request, State),
    next_state(closed, NewState);

closed(Frame, State)
  when element(1, Frame) == lcp ->
    ignore_frame_in(closed, Frame),
    next_state(closed, State).

%% -- stopped ----------------------------------------
stopped(down, _From, State) ->
    State1 = this_layer_started(State),
    reply(ok, starting, State1);
stopped(open, _From, State) ->
%% TODO:
%%   [r]   Restart option; see Open event discussion.
    reply(ok, stopped, State);
stopped(close, _From, State = #state{silent = Silent, passive = Passive})
  when Silent; Passive ->
    NewState = this_layer_finished(State),
    reply(ok, closed, NewState);
stopped(close, _From, State) ->
    reply(ok, closed, State);

stopped(Event, _From, State) ->
    invalid_event(stopped, Event),
    reply({error, invalid}, stopped, State).

%% RCR+, RCR-
stopped({lcp, 'CP-Configure-Request', Id, Options}, State) ->
    NewState0 = initialize_restart_count(State),
    NewState1 = resetci(NewState0),
    NewState2 = send_configure_request(false, NewState1),
    {Verdict, NewState3} = handle_configure_request(Id, Options, NewState2),
    case Verdict of
	ack ->
	    next_state(ack_sent, NewState3);
	_ ->
	    next_state(req_sent, NewState3)
    end;

%% RCA, RCN
stopped({lcp, Code, Id, _Options}, State)
  when Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    NewState = send_terminate_ack(Id, <<>>, State),
    next_state(stopped, NewState);

%% RTR
stopped({lcp, 'CP-Terminate-Request', Id, _Data}, State) ->
    NewState = send_terminate_ack(Id, <<>>, State),
    next_state(stopped, NewState);

%% RTA
stopped({lcp, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    next_state(stopped, State);

%% %% RXJ+
%% stopped({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     next_state(stopped, State);

%% RXJ-
stopped({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    NewState = this_layer_finished(State),
    next_state(stopped, NewState);

%% %% RXJ+
%% stopped({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     next_state(stopped, State);

%% RXJ-
stopped({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
    NewState = this_layer_finished(State),
    next_state(stopped, NewState);

%% RXR
stopped({lcp, 'CP-Discard-Request', _Id}, State) ->
    next_state(stopped, State);

%% RUC
stopped(Request, State)
  when element(1, Request) == lcp ->
    NewState = send_code_reject(Request, State),
    next_state(stopped, NewState);

stopped(Frame, State)
  when element(1, Frame) == lcp ->
    ignore_frame_in(stopped, Frame),
    next_state(stopped, State).

%% -- closing ----------------------------------------
closing(down, _From, State) ->
    reply(ok, initial, State);
closing(open, _From, State) ->
%% TODO:
%%   [r]   Restart option; see Open event discussion.
    reply(ok, stopping, State);
closing(close, _From, State) ->
    reply(ok, closed, State);

closing(Event, _From, State) ->
    invalid_event(closing, Event),
    reply({error, invalid}, closing, State).

closing({timeout, _Ref, _Msg}, State = #state{last_request = LastRequest}) ->
    case get_counter(LastRequest, State) of
        Cnt when Cnt > 0 ->
	    State1 = send_terminate_request(<<>>, State),
	    next_state(closing, State1);
	0 ->
	    State1 = this_layer_finished(State),
	    next_state(closed, State1)
    end;

%% RCR+, RCR-, RCA, RCN
closing({lcp, Code, _Id, _Options}, State)
  when Code == 'CP-Configure-Request';
       Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    next_state(closing, State);

%% RTR
closing({lcp, 'CP-Terminate-Request', Id, _Data}, State) ->
    NewState = send_terminate_ack(Id, <<>>, State),
    next_state(closing, NewState);

%% RTA
closing({lcp, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    NewState = this_layer_finished(State),
    next_state(closed, NewState);

%% %% RXJ+
%% closing({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     next_state(closing, State);

%% RXJ-
closing({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    NewState = this_layer_finished(State),
    next_state(closed, NewState);

%% %% RXJ+
%% closing({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     next_state(closing, State);

%% RXJ-
closing({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
    NewState = this_layer_finished(State),
    next_state(closed, NewState);

%% RXR
closing({lcp, 'CP-Discard-Request', _Id}, State) ->
    next_state(closing, State);

%% RUC
closing(Request, State)
  when element(1, Request) == lcp ->
    NewState = send_code_reject(Request, State),
    next_state(closing, NewState);

closing(Frame, State)
  when element(1, Frame) == lcp ->
    ignore_frame_in(closing, Frame),
    next_state(closing, State).

%% -- stopping ---------------------------------------
stopping(down, _From, State) ->
    reply(ok, starting, State);
stopping(open, _From, State) ->
%% TODO:
%%   [r]   Restart option; see Open event discussion.
    reply(ok, stopping, State);
stopping(close, _From, State) ->
    reply(ok, closing, State);

stopping(Event, _From, State) ->
    invalid_event(stopping, Event),
    reply({error, invalid}, stopping, State).

stopping({timeout, _Ref, _Msg}, State = #state{last_request = LastRequest}) ->
    case get_counter(LastRequest, State) of
        Cnt when Cnt > 0 ->
	    State1 = send_terminate_request(<<>>, State),
	    next_state(stopping, State1);
	0 ->
	    State1 = this_layer_finished(State),
	    next_state(stopped, State1)
    end;

%% RCR+, RCR-, RCA, RCN
stopping({lcp, Code, _Id, _Options}, State)
  when Code == 'CP-Configure-Request';
       Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    next_state(stopping, State);

%% RTR
stopping({lcp, 'CP-Terminate-Request', Id, _Data}, State) ->
    NewState = send_terminate_ack(Id, <<>>, State),
    next_state(stopping, NewState);

%% RTA
stopping({lcp, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    NewState = this_layer_finished(State),
    next_state(stopped, NewState);

%% %% RXJ+
%% stopping({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     next_state(stopping, State);

%% RXJ-
stopping({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    NewState = this_layer_finished(State),
    next_state(stopped, NewState);

%% %% RXJ+
%% stopping({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     next_state(stopping, State);

%% RXJ-
stopping({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
    NewState = this_layer_finished(State),
    next_state(closed, NewState);

%% RXR
stopping({lcp, 'CP-Discard-Request', _Id}, State) ->
    next_state(stopping, State);

%% RUC
stopping(Request, State)
  when element(1, Request) == lcp ->
    NewState = send_code_reject(Request, State),
    next_state(stopping, NewState);

stopping(Frame, State)
  when element(1, Frame) == lcp ->
    ignore_frame_in(stopping, Frame),
    next_state(stopping, State).

%% -- req_sent ---------------------------------------
req_sent(down, _From, State) ->
    reply(ok, starting, State);
req_sent(open, _From, State) ->
    reply(ok, req_sent, State);
req_sent(close, _From, State) ->
    State1 = initialize_restart_count(State),
    State2 = send_terminate_request(<<>>, State1),
    reply(ok, closing, State2);

req_sent(Event, _From, State) ->
    invalid_event(req_sent, Event),
    reply({error, invalid}, req_sent, State).

req_sent({timeout, _Ref, _Msg}, State = #state{last_request = LastRequest}) ->
    case get_counter(LastRequest, State) of
        Cnt when Cnt > 0 ->
	    State1 = send_configure_request(true, State),
	    next_state(req_sent, State1);
	0 ->
	    State1 = this_layer_finished(State),
%% TODO:
%%   [p]   Passive option; see Stopped state discussion.

	    next_state(stopped, State1)
    end;

%% RCR+, RCR-
req_sent({lcp, 'CP-Configure-Request', Id, Options}, State) ->
    {Verdict, NewState} = handle_configure_request(Id, Options, State),
    case Verdict of
	ack ->
	    %% RCR+
	    next_state(ack_sent, NewState);
	_ ->
	    %% RCR-
	    next_state(req_sent, NewState)
    end;

%% RCA
req_sent({lcp, 'CP-Configure-Ack', _Id, _Options}, State) ->
    NewState = initialize_restart_count(State),
    next_state(ack_rcvd, NewState);

%% RCN
req_sent({lcp, Code, _Id, _Options}, State)
  when Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    NewState0 = stop_timer(State),
    NewState1 = initialize_restart_count(NewState0),
    NewState2 = send_configure_request(false, NewState1),
    next_state(req_sent, NewState2);

%% RTR
req_sent({lcp, 'CP-Terminate-Request', Id, Data}, State) ->
    NewState = send_terminate_ack(Id, Data, State),
    next_state(req_sent, NewState);

%% RTA
req_sent({lcp, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    next_state(req_sent, State);

%% %% RXJ+
%% req_sent({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     next_state(req_sent, State);

%% RXJ-
req_sent({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    NewState = this_layer_finished(State),
    next_state(stopped, NewState);

%% %% RXJ+
%% req_sent({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     next_state(req_sent, State);

%% RXJ-
req_sent({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
    NewState = this_layer_finished(State),
    next_state(stopped, NewState);

%% RXR
req_sent({lcp, 'CP-Discard-Request', _Id}, State) ->
    next_state(req_sent, State);

%% RUC
req_sent(Request, State)
  when element(1, Request) == lcp ->
    NewState = send_code_reject(Request, State),
    next_state(req_sent, NewState);

req_sent(Frame, State)
  when element(1, Frame) == lcp ->
    ignore_frame_in(req_sent, Frame),
    next_state(req_sent, State).

%% -- ack_rcvd ---------------------------------------
ack_rcvd(down, _From, State) ->
    reply(ok, starting, State);
ack_rcvd(open, _From, State) ->
    reply(ok, ack_rcvd, State);
ack_rcvd(close, _From, State) ->
    State1 = initialize_restart_count(State),
    State2 = send_terminate_request(<<>>, State1),
    reply(ok, closing, State2);

ack_rcvd(Event, _From, State) ->
    invalid_event(ack_rcvd, Event),
    reply({error, invalid}, ack_rcvd, State).

ack_rcvd({timeout, _Ref, _Msg}, State = #state{last_request = LastRequest}) ->
    case get_counter(LastRequest, State) of
        Cnt when Cnt > 0 ->
	    State1 = send_configure_request(true, State),
	    next_state(ack_rcvd, State1);
	0 ->
	    State1 = this_layer_finished(State),
%% TODO:
%%   [p]   Passive option; see Stopped state discussion.

	    next_state(stopped, State1)
    end;

%% RCR+, RCR-
ack_rcvd({lcp, 'CP-Configure-Request', Id, Options}, State) ->
    {Verdict, NewState0} = handle_configure_request(Id, Options, State),
    case Verdict of
	ack ->
	    %% RCR+
	    NewState1 = this_layer_up(NewState0),
	    next_state(opened, NewState1);
	_ ->
	    %% RCR-
	    next_state(ack_rcvd, NewState0)
    end;

%% RCA, RCN
ack_rcvd({lcp, Code, _Id, _Options}, State)
  when Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
%% TODO:
%%   [x]   Crossed connection; see RCA event discussion.
    NewState0 = stop_timer(State),
    NewState1 = send_configure_request(false, NewState0),
    next_state(req_sent, NewState1);

%% RTR
ack_rcvd({lcp, 'CP-Terminate-Request', Id, Data}, State) ->
    NewState = send_terminate_ack(Id, Data, State),
    next_state(req_sent, NewState);

%% RTA
ack_rcvd({lcp, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    next_state(req_sent, State);

%% %% RXJ+
%% ack_rcvd({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     next_state(req_sent, State);

%% RXJ-
ack_rcvd({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    NewState = this_layer_finished(State),
    next_state(stopped, NewState);

%% %% RXJ+
%% ack_rcvd({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     next_state(req_sent, State);

%% RXJ-
ack_rcvd({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
    NewState = this_layer_finished(State),
    next_state(stopped, NewState);

%% RXR
ack_rcvd({lcp, 'CP-Discard-Request', _Id}, State) ->
    next_state(ack_rcvd, State);

%% RUC
ack_rcvd(Request, State)
  when element(1, Request) == lcp ->
    NewState = send_code_reject(Request, State),
    next_state(ack_rcvd, NewState);

ack_rcvd(Frame, State)
  when element(1, Frame) == lcp ->
    ignore_frame_in(ack_rcvd, Frame),
    next_state(ack_rcvd, State).

%% -- ack_sent ---------------------------------------
ack_sent(down, _From, State) ->
    reply(ok, starting, State);
ack_sent(open, _From, State) ->
    reply(ok, ack_sent, State);
ack_sent(close, _From, State) ->
    State1 = initialize_restart_count(State),
    State2 = send_terminate_request(<<>>, State1),
    reply(ok, closing, State2);

ack_sent(Event, _From, State) ->
    invalid_event(ack_sent, Event),
    reply({error, invalid}, ack_sent, State).

ack_sent({timeout, _Ref, _Msg}, State = #state{last_request = LastRequest}) ->
    case get_counter(LastRequest, State) of
        Cnt when Cnt > 0 ->
	    State1 = send_configure_request(true, State),
	    next_state(ack_sent, State1);
	0 ->
	    State1 = this_layer_finished(State),
%% TODO:
%%   [p]   Passive option; see Stopped state discussion.

	    next_state(stopped, State1)
    end;

%% RCR+, RCR-
ack_sent({lcp, 'CP-Configure-Request', Id, Options}, State) ->
    {Verdict, NewState0} = handle_configure_request(Id, Options, State),
    case Verdict of
	ack ->
	    %% RCR+
	    NewState1 = send_configure_ack(Id, Options, NewState0),
	    next_state(ack_sent, NewState1);
	_ ->
	    %% RCR-
	    next_state(req_sent, NewState0)
    end;

%% RCA
ack_sent({lcp, 'CP-Configure-Ack', _Id, _Options}, State) ->
    NewState0 = initialize_restart_count(State),
    NewState1 = this_layer_up(NewState0),
    next_state(opened, NewState1);

%% RCN
ack_sent({lcp, Code, _Id, _Options}, State)
  when Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
    NewState0 = stop_timer(State),
    NewState1 = initialize_restart_count(NewState0),
    NewState2 = send_configure_request(false, NewState1),
    next_state(ack_sent, NewState2);

%% RTR
ack_sent({lcp, 'CP-Terminate-Request', Id, Data}, State) ->
    NewState = send_terminate_ack(Id, Data, State),
    next_state(req_sent, NewState);

%% RTA
ack_sent({lcp, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    next_state(ack_sent, State);

%% %% RXJ+
%% ack_sent({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     next_state(ack_sent, State);

%% RXJ-
ack_sent({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    NewState = this_layer_finished(State),
    next_state(stopped, NewState);

%% %% RXJ+
%% ack_sent({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     next_state(ack_sent, State);

%% RXJ-
ack_sent({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
    NewState = this_layer_finished(State),
    next_state(stopped, NewState);

%% RXR
ack_sent({lcp, 'CP-Discard-Request', _Id}, State) ->
    next_state(ack_sent, State);

%% RUC
ack_sent(Request, State)
  when element(1, Request) == lcp ->
    NewState = send_code_reject(Request, State),
    next_state(ack_sent, NewState);

ack_sent(Frame, State)
  when element(1, Frame) == lcp ->
    ignore_frame_in(ack_sent, Frame),
    next_state(ack_sent, State).

%% -- opened -----------------------------------------
opened(down, _From, State) ->
    State1 = this_layer_down(State),
    reply(ok, starting, State1);
opened(open, _From, State) ->
%% TODO:
%%   [r]   Restart option; see Open event discussion.
    reply(ok, opened, State);
opened(close, _From, State) ->
    State1 = initialize_restart_count(State),
    State2 = send_terminate_request(<<>>, State1),
    reply(ok, closing, State2);

opened(Event, _From, State) ->
    invalid_event(opened, Event),
    reply({error, invalid}, opened, State).

%% RCR+, RCR-
opened({lcp, 'CP-Configure-Request', Id, Options}, State) ->
    NewState0 = this_layer_down(State),
    NewState1 = resetci(NewState0),
    NewState2 = send_configure_request(false, NewState1),
    {Verdict, NewState3} = handle_configure_request(Id, Options, NewState2),
    case Verdict of
	ack ->
	    %% RCR+
	    next_state(ack_sent, NewState3);
	_ ->
	    %% RCR-
	    next_state(req_sent, NewState3)
    end;

%% RCA, RCN
opened({lcp, Code, _Id, _Options}, State)
  when Code == 'CP-Configure-Ack';
       Code == 'CP-Configure-Nak';
       Code == 'CP-Configure-Reject' ->
%% TODO:
%%   apply Nak/Reject to State
    NewState0 = this_layer_down(State),
    NewState1 = resetci(NewState0),
    NewState2 = send_configure_request(false, NewState1),
%% TODO:
%%   [x]   Crossed connection; see RCA event discussion.
    next_state(req_sent, NewState2);

%% RTR
opened({lcp, 'CP-Terminate-Request', Id, Data}, State) ->
    NewState0 = this_layer_down(State),
    NewState1 = zero_restart_count(NewState0),
    NewState2 = send_terminate_ack(Id, Data, NewState1),
    next_state(stopping, NewState2);

%% RTA
opened({lcp, 'CP-Terminate-Ack', _Id, _Data}, State) ->
    NewState0 = this_layer_down(State),
    NewState1 = resetci(NewState0),
    NewState2 = send_configure_request(false, NewState1),
    next_state(req_sent, NewState2);

%% %% RXJ+
%% opened({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
%%     next_state(opened, State);

%% RXJ-
opened({lcp, 'CP-Code-Reject', _Id, _RejectedPacket}, State) ->
    NewState0 = this_layer_down(State),
    NewState1 = initialize_restart_count(NewState0),
    NewState2 = send_terminate_request(<<>>, NewState1),
    next_state(stopping, NewState2);

%% %% RXJ+
%% opened({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
%%     next_state(opened, State);

%% RXJ-
opened({lcp, 'CP-Protocol-Reject', _Id, _RejectedProtocol, _RejectedInfo}, State) ->
    NewState0 = this_layer_down(State),
    NewState1 = initialize_restart_count(NewState0),
    NewState2 = send_terminate_request(<<>>, NewState1),
    next_state(stopping, NewState2);

%% RXR
opened({lcp, 'CP-Discard-Request', _Id}, State) ->
    next_state(opened, State);

opened({lcp, 'CP-Echo-Request', Id, Data}, State) ->
    NewState = send_echo_reply(Id, Data, State),
    next_state(opened, NewState);

%% RUC
opened(Request, State)
  when element(1, Request) == lcp ->
    NewState = send_code_reject(Request, State),
    next_state(opened, NewState);

opened(Frame, State)
  when element(1, Frame) == lcp ->
    ignore_frame_in(opened, Frame),
    next_state(opened, State).

%% ---------------------------------------------------

handle_event(Msg = {lcp, 'CP-Configure-Ack', Id, Options}, StateName, State) ->
    case handle_configure_ack(Id, Options, State) of
	false ->
	    io:format("Ignoring ~p in state ~p~n", [Msg, StateName]),
	    next_state(StateName, State);
	NewState ->
	    ?MODULE:StateName(Msg, NewState)
    end;

handle_event(Msg = {lcp, 'CP-Configure-Nak', Id, Options}, StateName, State) ->
    case handle_configure_nak(StateName /= opened, Id, Options, State) of
	false ->
	    io:format("Ignoring ~p in state ~p~n", [Msg, StateName]),
	    next_state(StateName, State);
	NewState ->
	    ?MODULE:StateName(Msg, NewState)
    end;

handle_event(Msg = {lcp, 'CP-Configure-Reject', Id, Options}, StateName, State) ->
    case handle_configure_rej(StateName /= opened, Id, Options, State) of
	false ->
	    io:format("Ignoring ~p in state ~p~n", [Msg, StateName]),
	    next_state(StateName, State);
	NewState ->
	    ?MODULE:StateName(Msg, NewState)
    end;

handle_event(Msg, StateName, State)
  when element(1, Msg) == lcp ->
    ?MODULE:StateName(Msg, State);

handle_event(Event, StateName, State) ->
    io:format("Event: ~p~n", [Event]),
    next_state(StateName, State).

handle_sync_event(Event, _From, StateName, State) ->
    io:format("SyncEvent: ~p~n", [Event]),
    Reply = ok,
    reply(Reply, StateName, State).

handle_info(Info, StateName, State) ->
    io:format("Info: ~p~n", [Info]),
    next_state(StateName, State).

terminate(_Reason, _StateName, _State) ->
    io:format("ppp_lcp ~p terminated~n", [self()]),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

link_send(Link, Data) ->
    ppp_link:send(Link, Data).

send_packet(Packet, State = #state{link = Link}) ->
    io:format("Sending: ~p~n", [Packet]),
    Data = ppp_frame:encode(Packet),
    link_send(Link, Data),
    State.

ignore_frame_in(StateName, Frame) ->
    io:format("ignoring LCP ~p in state ~p (~p)~n", [element(2, Frame), StateName, Frame]).

invalid_event(StateName, Event) ->
    io:format("invalid event ~p in state ~p~n", [Event, StateName]).

get_counter('Terminate-Request', State) ->
    State#state.term_restart_count;
get_counter('Configure-Request', State) ->
    State#state.conf_restart_count;
get_counter('Configure-Nak', State) ->
    State#state.failure_count.

dec_counter('Terminate-Request', State = #state{term_restart_count = Count})
  when Count > 0 ->
    State#state{term_restart_count = Count - 1};
dec_counter('Configure-Request', State = #state{conf_restart_count = Count})
  when Count > 0 ->
    State#state{conf_restart_count = Count - 1};
dec_counter('Configure-Nak', State = #state{failure_count = Count})
  when Count > 0 ->
    State#state{failure_count = Count - 1}.

reply(Reply, NextStateName, State = #state{timer = Timer})
  when is_reference(Timer) andalso
       (NextStateName == initial orelse
	NextStateName == starting orelse
	NextStateName == closed orelse
	NextStateName == stopped orelse
	NextStateName == opened) ->
    NewState = stop_timer(State),
    io:format("FSM: going to: ~p~n", [NextStateName]),
    {reply, Reply, NextStateName, NewState};

reply(Reply, NextStateName, State) ->
    io:format("FSM: going to: ~p~n", [NextStateName]),
    {reply, Reply, NextStateName, State}.

next_state(NextStateName, State = #state{timer = Timer})
  when is_reference(Timer) andalso
       (NextStateName == initial orelse
	NextStateName == starting orelse
	NextStateName == closed orelse
	NextStateName == stopped orelse
	NextStateName == opened) ->
    NewState = stop_timer(State),
    io:format("FSM: going to: ~p~n", [NextStateName]),
    {next_state, NextStateName, NewState};

next_state(NextStateName, State) ->
    io:format("FSM: going to: ~p~n", [NextStateName]),
    {next_state, NextStateName, State}.

%%===================================================================
%% Option Generation
-define(AUTH_OPTS_R, [pap, chap, eap]).
-define(LCP_OPTS, [mru , asyncmap, auth, quality, callback, magic, pfc, acfc, mrru, epdisc, ssnhf]).

-spec lcp_addci(AddOpt :: atom(),
		GotOpts :: #lcp_opts{}) -> ppp_option().

lcp_addci(mru, #lcp_opts{neg_mru = true, mru = GotMRU})
  when GotMRU /= ?DEFMRU ->
    {mru, GotMRU};

lcp_addci(asyncmap, #lcp_opts{neg_asyncmap = true, asyncmap = GotACCM})
  when GotACCM /= 16#ffffffff ->
    {asyncmap, GotACCM};
    
lcp_addci(auth, #lcp_opts{neg_auth = GotAuth})
  when is_list(GotAuth) ->
    suggest_auth(GotAuth);

lcp_addci(auth, #lcp_opts{neg_auth = GotAuth}) ->
    io:format("lcp_addci: skiping auth: ~p~n", [GotAuth]),
    [];

lcp_addci(quality, #lcp_opts{neg_lqr = true, lqr_period = GotPeriod}) ->
    {quality, ?PPP_LQR, GotPeriod};

lcp_addci(callback, #lcp_opts{neg_cbcp = true}) ->
    {callback, ?CBCP_OPT};

lcp_addci(magic, #lcp_opts{neg_magicnumber = true, magicnumber = GotMagic}) ->
    {magic, GotMagic};

lcp_addci(pfc, #lcp_opts{neg_pcompression = true}) ->
    pfc;

lcp_addci(acfc, #lcp_opts{neg_accompression = true}) ->
    acfc;

lcp_addci(mrru, #lcp_opts{neg_mrru = true, mrru = GotMRRU}) ->
    {mrru, GotMRRU};

lcp_addci(ssnhf, #lcp_opts{neg_ssnhf = true}) ->
    ssnhf;

lcp_addci(epdisc,
	  #lcp_opts{neg_endpoint = true, endpoint =
			#epdisc{class = GotClass, address = GotAddress}}) ->
    {epdisc, GotClass, GotAddress};

lcp_addci(_, _) ->
    [].

lcp_addcis(GotOpts) ->
    [lcp_addci(Opt, GotOpts) || Opt <- ?LCP_OPTS].

%%===================================================================
%% Option Validations
-spec lcp_nakci(NakOpt :: ppp_option(),
		GotOpts :: #lcp_opts{},
		WantOpts :: #lcp_opts{},
		TryOpts :: #lcp_opts{},
		NakOpts :: #lcp_opts{}) -> {#lcp_opts{}, #lcp_opts{}}.

%%
%% We don't care if they want to send us smaller packets than
%% we want.  Therefore, accept any MRU less than what we asked for,
%% but then ignore the new value when setting the MRU in the kernel.
%% If they send us a bigger MRU than what we asked, accept it, up to
%% the limit of the default MRU we'd get if we didn't negotiate.
%%
lcp_nakci({mru, NakMRU}, GotOpts = #lcp_opts{neg_mru = true}, WantOpts, TryOpts, NakOpts)
  when GotOpts#lcp_opts.mru /= ?DEFMRU ->
    T1 = if NakMRU =< WantOpts#lcp_opts.mru orelse NakMRU =< ?DEFMRU ->
		 TryOpts#lcp_opts{mru = NakMRU};
	    true -> TryOpts
	 end,
    N1 = NakOpts#lcp_opts{neg_mru = true},
    {T1, N1};

lcp_nakci({mru, NakMRU}, GotOpts = #lcp_opts{neg_mru = GotNegMRU}, _WantOpts, TryOpts, NakOpts = #lcp_opts{neg_mru = false})
  when not (GotNegMRU and GotOpts#lcp_opts.mru /= ?DEFMRU) ->
    T1 = if NakMRU =< ?DEFMRU ->
		 TryOpts#lcp_opts{mru = NakMRU};
	    true -> TryOpts
	 end,
    N1 = NakOpts#lcp_opts{neg_mru = true},
    {T1, N1};

%%
%% Add any characters they want to our (receive-side) asyncmap.
%%
lcp_nakci({asyncmap, NakACCM}, #lcp_opts{neg_asyncmap = true, asyncmap = GotACCM}, _WantOpts, TryOpts, NakOpts)
  when GotACCM /= 16#ffffffff ->
    T1 = TryOpts#lcp_opts{asyncmap = GotACCM bor NakACCM},
    N1 = NakOpts#lcp_opts{neg_asyncmap = true},
    {T1, N1};

lcp_nakci({asyncmap, _}, #lcp_opts{neg_asyncmap = GotNegACCM, asyncmap = GotACCM}, _WantOpts, TryOpts, NakOpts = #lcp_opts{neg_asyncmap = false})
  when not (GotNegACCM and GotACCM /= 16#ffffffff) ->
    N1 = NakOpts#lcp_opts{neg_asyncmap = true},
    {TryOpts, N1};

%%
%% If they've nak'd our authentication-protocol, check whether
%% they are proposing a different protocol, or a different
%% hash algorithm for CHAP.
%%
lcp_nakci({auth, NakAuth, _}, #lcp_opts{neg_auth = GotAuth}, _WantOpts, TryOpts, NakOpts)
  when NakAuth == eap; NakAuth == pap ->
    case GotAuth of
	[NakAuth|_] ->
	    false;
	[LastAuth|TryAuth] ->
	    T1 = TryOpts#lcp_opts{neg_auth = TryAuth},
	    io:format("neg_auth: ~p~n", [NakOpts#lcp_opts.neg_auth]),
	    io:format("NakAuth: ~p~n", [NakAuth]),
	    N1 = NakOpts#lcp_opts{neg_auth = NakOpts#lcp_opts.neg_auth ++ [LastAuth]},
	    {T1, N1}
    end;

lcp_nakci({auth, NakAuth, NakMDType}, #lcp_opts{neg_auth = GotAuth}, _WantOpts, TryOpts, NakOpts)
  when NakAuth == chap ->
    case GotAuth of
	[{NakAuth, [NakMDType|_]}|_] ->
	    %% Whoops, they Nak'd our algorithm of choice
	    %% but then suggested it back to us.
	    false;
	[LastAuth|RestAuth] ->
	    case LastAuth of
		{chap, _} -> NextAuth = LastAuth;
		_         -> NextAuth = RestAuth
		end,
	    TryMDTypes = suggest_md_type(NakMDType, proplists:get_value(NakAuth, NextAuth)),
	    TryAuth = lists:keyreplace(NakAuth, 1, NextAuth, {NakAuth, TryMDTypes}),
	    T1 = TryOpts#lcp_opts{neg_auth = TryAuth},

	    %% FIXME: too simplistic..
	    N1 = NakOpts#lcp_opts{neg_auth = NakOpts#lcp_opts.neg_auth ++ [NakAuth]},
	    {T1, N1}
    end;

lcp_nakci({auth, NakAuth, _}, #lcp_opts{neg_auth = []}, _WantOpts, TryOpts, NakOpts = #lcp_opts{neg_auth = []}) ->
    N1 = NakOpts#lcp_opts{neg_auth = NakOpts#lcp_opts.neg_auth ++ NakAuth},
    {TryOpts, N1};

lcp_nakci({quality, NakQR, NakPeriod}, #lcp_opts{neg_lqr = true}, _WantOpts, TryOpts, NakOpts) ->
    if NakQR /= ?PPP_LQR -> 
	    T1 = TryOpts#lcp_opts{neg_lqr = false};
       true ->
	    T1 = TryOpts#lcp_opts{lqr_period = NakPeriod}
    end,
    N1 = NakOpts#lcp_opts{neg_lqr = true},
    {T1, N1};

lcp_nakci({quality, _, _}, #lcp_opts{neg_lqr = false}, _WantOpts, TryOpts, NakOpts = #lcp_opts{neg_lqr = false}) ->
    N1 = NakOpts#lcp_opts{neg_lqr = true},
    {TryOpts, N1};

lcp_nakci({callback, ?CBCP_OPT}, #lcp_opts{neg_cbcp = true}, _WantOpts, TryOpts, NakOpts) ->
    T1 = TryOpts#lcp_opts{neg_cbcp = false},
    N1 = NakOpts#lcp_opts{neg_cbcp = true},
    {T1, N1};

lcp_nakci({magic, _}, #lcp_opts{neg_magicnumber = true}, _WantOpts, TryOpts, NakOpts) ->
    T1 = TryOpts#lcp_opts{magicnumber = random:uniform(16#ffffffff)},
    N1 = NakOpts#lcp_opts{neg_magicnumber = true},
    {T1, N1};

lcp_nakci({magic, _}, #lcp_opts{neg_magicnumber = false}, _WantOpts, TryOpts, NakOpts = #lcp_opts{neg_magicnumber = false}) ->
    N1 = NakOpts#lcp_opts{neg_magicnumber = true},
    {TryOpts, N1};

%% Peer shouldn't send Nak for protocol compression or
%% address/control compression requests; they should send
%% a Reject instead.  If they send a Nak, treat it as a Reject.
lcp_nakci(pfc, #lcp_opts{neg_pcompression = true}, _WantOpts, TryOpts, NakOpts) ->
    N1 = NakOpts#lcp_opts{neg_pcompression = true},
    {TryOpts, N1};

lcp_nakci(pfc, #lcp_opts{neg_pcompression = false}, _WantOpts, TryOpts, NakOpts = #lcp_opts{neg_pcompression = false}) ->
    N1 = NakOpts#lcp_opts{neg_pcompression = true},
    {TryOpts, N1};

lcp_nakci(acfc, #lcp_opts{neg_accompression = true}, _WantOpts, TryOpts, NakOpts) ->
    N1 = NakOpts#lcp_opts{neg_accompression = true},
    {TryOpts, N1};

lcp_nakci(acfc, #lcp_opts{neg_accompression = false}, _WantOpts, TryOpts, NakOpts = #lcp_opts{neg_accompression = false}) ->
    N1 = NakOpts#lcp_opts{neg_accompression = true},
    {TryOpts, N1};

lcp_nakci({mrru, NakMRRU}, #lcp_opts{neg_mrru = true}, WantOpts, TryOpts, NakOpts) ->
    if NakMRRU < WantOpts#lcp_opts.mrru ->
	    T1 = TryOpts#lcp_opts{mrru = NakMRRU};
       true ->
	    T1 = TryOpts
    end,
    N1 = NakOpts#lcp_opts{neg_mrru = true},
    {T1, N1};

lcp_nakci({mrru, _}, #lcp_opts{neg_mrru = false}, _WantOpts, TryOpts, NakOpts = #lcp_opts{neg_mrru = false}) ->
    N1 = NakOpts#lcp_opts{neg_mrru = true},
    {TryOpts, N1};

%% Nak for short sequence numbers shouldn't be sent, treat it
%% like a reject.
lcp_nakci(ssnhf, #lcp_opts{neg_ssnhf = true}, _WantOpts, TryOpts, NakOpts) ->
    N1 = NakOpts#lcp_opts{neg_ssnhf = true},
    {TryOpts, N1};

lcp_nakci(ssnhf, #lcp_opts{neg_ssnhf = false}, _WantOpts, TryOpts, NakOpts = #lcp_opts{neg_ssnhf = false}) ->
    N1 = NakOpts#lcp_opts{neg_ssnhf = true},
    {TryOpts, N1};

%% Nak of the endpoint discriminator option is not permitted,
%% treat it like a reject.
lcp_nakci({epdisc, _, _}, #lcp_opts{neg_endpoint = true}, _WantOpts, TryOpts, NakOpts) ->
    N1 = NakOpts#lcp_opts{neg_endpoint = true},
    {TryOpts, N1};

lcp_nakci({epdisc, _, _}, #lcp_opts{neg_endpoint = false}, _WantOpts, TryOpts, NakOpts = #lcp_opts{neg_endpoint = false}) ->
    N1 = NakOpts#lcp_opts{neg_endpoint = true},
    {TryOpts, N1};

lcp_nakci(_, _, _, _, _) ->
    false.

%% drop the first (currently prefered) because it has been rejected
suggest_md_type(Prefered, [_|Available]) ->
    case proplists:get_bool(Prefered, Available) of
	true ->
	    Prefered ++ proplists:delete(Prefered, Available);
	false -> Available
    end.

%%TODO: does this really matter?
%%
%% RFC1661 says:
%%   Options from the Configure-Request MUST NOT be reordered
%% we do not enforce ordering here, pppd does
%%
%% Note: on generating Ack/Naks we do preserve ordering!
%%
lcp_nakcis([], _, _, TryOpts, _) ->
    io:format("lcp_nakcis: ~p~n", [TryOpts]),
    TryOpts;
lcp_nakcis([Opt|Options], GotOpts, WantOpts, TryOpts, NakOpts) ->
    case lcp_nakci(Opt, GotOpts, WantOpts, TryOpts, NakOpts) of
	{NewTryOpts, NewNakOpts} ->
	    lcp_nakcis(Options, GotOpts, WantOpts, NewTryOpts, NewNakOpts);
	_ ->
	    io:format("lcp_nakcis: received bad Nakt!~n"),
	    false
    end.

-spec lcp_rejci(RejOpt :: ppp_option(),
		GotOpts :: #lcp_opts{},
		TryOpts :: #lcp_opts{}) -> #lcp_opts{}.

lcp_rejci({mru, MRU}, #lcp_opts{neg_mru = true, mru = MRU}, TryOpts) ->
    TryOpts#lcp_opts{neg_mru = false};

lcp_rejci({asyncmap, ACCM}, #lcp_opts{neg_asyncmap = true, asyncmap = ACCM}, TryOpts) ->
    TryOpts#lcp_opts{neg_asyncmap = false};

lcp_rejci({auth, RejAuth, _}, #lcp_opts{neg_auth = GotAuth}, TryOpts = #lcp_opts{neg_auth = TryAuth})
  when RejAuth == pap; RejAuth == eap ->
    case proplists:get_bool(RejAuth, GotAuth) of
	true -> TryOpts#lcp_opts{neg_auth = proplists:delete(RejAuth, TryAuth)};
	_    -> false
    end;

lcp_rejci({auth, RejAuth, RejMDType}, #lcp_opts{neg_auth = GotAuth}, TryOpts = #lcp_opts{neg_auth = TryAuth})
  when RejAuth == chap ->
    case proplists:get_value(RejAuth, GotAuth) of
	[RejMDType] ->
	    %% last CHAP MD
	    TryOpts#lcp_opts{neg_auth = proplists:delete(RejAuth, TryAuth)};
	TryMDType when is_list(TryMDType) ->
	    case proplists:get_bool(RejMDType, TryMDType) of
		true ->
		    NewTryMDType = proplists:delete(RejMDType, TryMDType),
		    TryOpts#lcp_opts{neg_auth = lists:keyreplace(RejAuth, 1, TryAuth, NewTryMDType)};
		_ ->
		    false
	    end
    end;

lcp_rejci({quality, ?PPP_LQR, Period}, #lcp_opts{neg_lqr = true, lqr_period = Period}, TryOpts) ->
    TryOpts#lcp_opts{neg_lqr = false};

lcp_rejci({callback, ?CBCP_OPT}, #lcp_opts{neg_cbcp = true}, TryOpts) ->
    TryOpts#lcp_opts{neg_cbcp = false};

lcp_rejci({magic, Magic}, #lcp_opts{neg_magicnumber = true, magicnumber = Magic}, TryOpts) ->
    TryOpts#lcp_opts{neg_magicnumber = false};

lcp_rejci(pfc, #lcp_opts{neg_pcompression = true}, TryOpts) ->
    TryOpts#lcp_opts{neg_pcompression = false};

lcp_rejci(acfc, #lcp_opts{neg_accompression = true}, TryOpts) ->
    io:format("acfs rejected~n"),
    TryOpts#lcp_opts{neg_accompression = false};

lcp_rejci({mrru, MRRU}, #lcp_opts{neg_mrru = true, mrru = MRRU}, TryOpts) ->
    TryOpts#lcp_opts{neg_mrru = false};

lcp_rejci(ssnhf, #lcp_opts{neg_ssnhf = true}, TryOpts) ->
    TryOpts#lcp_opts{neg_ssnhf = false};

lcp_rejci({epdisc, Class, Address},
	       #lcp_opts{neg_endpoint = true, endpoint =
			     #epdisc{class = Class, address = Address}}, TryOpts) ->
    TryOpts#lcp_opts{neg_endpoint = false};

lcp_rejci(_, _, _) ->
    false.

%%TODO: does this really matter?
%%
%% RFC1661 says:
%%   Options from the Configure-Request MUST NOT be reordered
%% we do not enforce ordering here, pppd does
%%
%% Note: on generating Ack/Naks we do preserve ordering!
%%
lcp_rejcis([], _, TryOpts) ->
    TryOpts;
lcp_rejcis([RejOpt|RejOpts], GotOpts, TryOpts) ->
    case lcp_rejci(RejOpt, GotOpts, TryOpts) of
	NewTryOpts when is_record(NewTryOpts, lcp_opts) ->
	    lcp_rejcis(RejOpts, GotOpts, NewTryOpts);
	_ ->
	    io:format("lcp_rejcis: received bad Reject!~n"),
	    false
    end.

-spec lcp_ackci(AckOpt :: ppp_option(),
		     GotOpts :: #lcp_opts{}) -> true | false.

lcp_ackci({mru, AckMRU}, #lcp_opts{neg_mru = GotIt, mru = GotMRU})
  when GotMRU /= ?DEFMRU ->
    GotIt and (AckMRU == GotMRU);

lcp_ackci({asyncmap, AckACCM}, #lcp_opts{neg_asyncmap = GotIt, asyncmap = GotACCM})
  when GotACCM /= 16#ffffffff ->
    GotIt and (AckACCM == GotACCM);
    
lcp_ackci({auth, AckAuth, _}, #lcp_opts{neg_auth = GotAuth})
  when AckAuth == pap; AckAuth == eap ->
    io:format("AckAuth: ~p~n", [AckAuth]),
    io:format("GotAuth: ~p~n", [GotAuth]),
    proplists:get_bool(AckAuth, GotAuth);
lcp_ackci({auth, AckAuth, AckMDType}, #lcp_opts{neg_auth = GotAuth})
  when AckAuth == chap ->
    %% FIXME: this needs to be changed....
    GotAuth == {AckAuth, AckMDType};

lcp_ackci({quality, AckQP, AckPeriod}, #lcp_opts{neg_lqr = GotIt, lqr_period = GotPeriod}) ->
    GotIt and (AckQP == ?PPP_LQR) and (AckPeriod == GotPeriod);

lcp_ackci({callback, Opt}, #lcp_opts{neg_cbcp = GotIt}) ->
    GotIt and (Opt == ?CBCP_OPT);

lcp_ackci({magic, AckMagic}, #lcp_opts{neg_magicnumber = GotIt, magicnumber = GotMagic}) ->
    GotIt and (AckMagic == GotMagic);

lcp_ackci(pfc, #lcp_opts{neg_pcompression = GotIt}) ->
    GotIt;

lcp_ackci(acfc, #lcp_opts{neg_accompression = GotIt}) ->
    GotIt;

lcp_ackci({mrru, AckMRRU}, #lcp_opts{neg_mrru = GotIt, mrru = GotMRRU}) ->
    GotIt and (AckMRRU == GotMRRU);

lcp_ackci(ssnhf, #lcp_opts{neg_ssnhf = GotIt}) ->
    GotIt;

lcp_ackci({epdisc, AckClass, AckAddress},
	       #lcp_opts{neg_endpoint = GotIt, endpoint =
			     #epdisc{class = GotClass, address = GotAddress}}) ->
    GotIt and (AckClass == GotClass) and (AckAddress == GotAddress);
lcp_ackci(Ack, _) ->
    io:format("invalid Ack: ~p~n", [Ack]),
    false.

%%TODO: does this really matter?
%%
%% RFC1661 says:
%%   Options from the Configure-Request MUST NOT be reordered
%% we do not enforce ordering here, pppd does
%%
%% Note: on generating Ack/Naks we do preserve ordering!
%%
lcp_ackcis([], _) ->
    true;
lcp_ackcis([AckOpt|AckOpts], GotOpts) ->
    case lcp_ackci(AckOpt, GotOpts) of
	false ->
	    io:format("lcp_ackcis: received bad Ack! ~p, ~p~n", [AckOpt, GotOpts]),
	    false;
	_ ->
	    lcp_ackcis(AckOpts, GotOpts)
    end.

-spec lcp_reqci(ReqOpt :: ppp_option(),
		     AllowedOpts :: #lcp_opts{},
		     GotOpts :: #lcp_opts{},
		     HisOpts :: #lcp_opts{}) ->
			    {Verdict :: atom() | {atom() | ppp_option()}, HisOptsNew :: #lcp_opts{}}.

lcp_reqci({mru, ReqMRU}, #lcp_opts{neg_mru = true}, _, HisOpts) ->
    if
	ReqMRU < ?MINMRU ->
	    Verdict = {nack, {mru, ?MINMRU}},
	    HisOptsNew = HisOpts;
	true -> 
	    Verdict = ack,
	    HisOptsNew = HisOpts#lcp_opts{neg_mru = true, mru = ReqMRU}
    end,
    {Verdict, HisOptsNew};

lcp_reqci({asyncmap, ReqACCM}, #lcp_opts{neg_asyncmap = true, asyncmap = AllowedACCM}, _, HisOpts) ->
    if
	%% Asyncmap must have set at least the bits
	%% which are set in AllowedOpts#lcp_opts.asyncmap

	AllowedACCM band bnot ReqACCM /= 0 ->
	    Verdict = {nack, {asyncmap, AllowedACCM bor ReqACCM}},
	    HisOptsNew = HisOpts;
	true -> 
	    Verdict = ack,
	    HisOptsNew = HisOpts#lcp_opts{neg_asyncmap = true, asyncmap = ReqACCM}
    end,
    {Verdict, HisOptsNew};

lcp_reqci({auth, _, _}, #lcp_opts{neg_auth = PermitedAuth}, _, HisOpts)
  when not is_list(PermitedAuth) orelse PermitedAuth == [] ->
    io:format("No auth is possible~n"),
    {rej, HisOpts};

%% Authtype must be PAP, CHAP, or EAP.
%%
%% Note: if more than one of ao->neg_upap, ao->neg_chap, and
%% ao->neg_eap are set, and the peer sends a Configure-Request
%% with two or more authenticate-protocol requests, then we will
%% reject the second request.
%% Whether we end up doing CHAP, UPAP, or EAP depends then on
%% the ordering of the CIs in the peer's Configure-Request.

lcp_reqci({auth, ReqAuth, _}, _, _, HisOpts = #lcp_opts{neg_auth = HisAuth})
  when HisAuth /= none ->
    io:format("lcp_reqci: rcvd AUTHTYPE ~p, rejecting...~n", [ReqAuth]),
    {rej, HisOpts};
lcp_reqci({auth, ReqAuth, _}, #lcp_opts{neg_auth = PermitedAuth}, _, HisOpts)
  when ReqAuth == pap; ReqAuth == eap ->
    case proplists:get_bool(ReqAuth, PermitedAuth) of
	true ->
	    Verdict = ack,
	    HisOptsNew = HisOpts#lcp_opts{neg_auth = ReqAuth};
	_ ->
	    Verdict = {nack, suggest_auth(PermitedAuth)},
	    HisOptsNew = HisOpts
    end,
    {Verdict, HisOptsNew};

lcp_reqci({auth, ReqAuth, ReqMDType}, #lcp_opts{neg_auth = PermitedAuth}, _, HisOpts)
  when ReqAuth == chap ->
    case proplists:get_value(ReqAuth, PermitedAuth) of
	 PermiteMDTypes when is_list(PermiteMDTypes) andalso PermiteMDTypes /= [] ->
	    case proplists:get_bool(ReqMDType, PermiteMDTypes) of
		true ->
		    Verdict = ack,
		    HisOptsNew = HisOpts#lcp_opts{neg_auth = {ReqAuth, ReqMDType}};
		_ ->
		    Verdict = {nack, suggest_auth(proplists:delete(chap, PermitedAuth))},
		    HisOptsNew = HisOpts
		end;
	_ ->
	    Verdict = {nack, suggest_auth(proplists:delete(chap, PermitedAuth))},
	    HisOptsNew = HisOpts
    end,
    {Verdict, HisOptsNew};

lcp_reqci({quality, ReqQP, ReqData}, #lcp_opts{neg_lqr = true, lqr_period = Period}, #lcp_opts{}, HisOpts = #lcp_opts{}) ->
    if
	ReqQP == ?PPP_LQR ->
	    Verdict = ack,
	    HisOptsNew = HisOpts#lcp_opts{neg_lqr = true, lqr_period = ReqData};
	true ->
	    Verdict = {nack, {quality, ?PPP_LQR, Period}},
	    HisOptsNew = HisOpts
    end,
    {Verdict, HisOptsNew};

lcp_reqci({magic, ReqMagic},
	       #lcp_opts{neg_magicnumber = AllowedNeg},
	       #lcp_opts{neg_magicnumber = GotNeg, magicnumber = GotMagic},
	       HisOpts = #lcp_opts{})
  when AllowedNeg == true; GotNeg == true ->
    if
	GotNeg andalso ReqMagic == GotMagic ->
	    Verdict = {rej, {magic, random:uniform(16#ffffffff)}},
	    HisOptsNew = HisOpts;
	true ->
	    Verdict = ack,
	    HisOptsNew = HisOpts#lcp_opts{neg_magicnumber = true, magicnumber = ReqMagic}
    end,
    {Verdict, HisOptsNew};

lcp_reqci(pfc, #lcp_opts{neg_pcompression = true}, _, HisOpts) ->
    Verdict = ack,
    HisOptsNew = HisOpts#lcp_opts{neg_pcompression = true},
    {Verdict, HisOptsNew};

lcp_reqci(acfc, #lcp_opts{neg_accompression = true}, _, HisOpts) ->
    Verdict = ack,
    HisOptsNew = HisOpts#lcp_opts{neg_accompression = true},
    {Verdict, HisOptsNew};

%% TODO: multilink check
lcp_reqci({mrru, ReqMRRU}, #lcp_opts{neg_mrru = true}, _, HisOpts) ->
    Verdict = ack,
    HisOptsNew = HisOpts#lcp_opts{neg_mrru = true, mrru = ReqMRRU},
    {Verdict, HisOptsNew};

lcp_reqci(ssnhf, #lcp_opts{neg_ssnhf = true}, _, HisOpts) ->
    Verdict = ack,
    HisOptsNew = HisOpts#lcp_opts{neg_ssnhf = true},
    {Verdict, HisOptsNew};

lcp_reqci({epdisc, ReqClass, ReqAddress}, #lcp_opts{neg_endpoint = true}, _, HisOpts) ->
    Verdict = ack,
    HisOptsNew = HisOpts#lcp_opts{neg_endpoint = true, endpoint = #epdisc{class = ReqClass, address = ReqAddress}},
    {Verdict, HisOptsNew};

lcp_reqci(Req, _, _, HisOpts) ->
    io:format("lcp_reqci: rejecting: ~p~n", [Req]),
    io:format("His: ~p~n", [HisOpts]),
    {rej, HisOpts}.

suggest_auth(PermitedAuths) ->
    suggest_auth(PermitedAuths, [eap, chap, pap]).
suggest_auth(_, []) ->
    [];
suggest_auth(PermitedAuths, [Auth|Rest]) ->
    case proplists:get_value(Auth, PermitedAuths, false) of
	false ->
	    suggest_auth(PermitedAuths, Rest);
	true ->
	    {auth, Auth, none};
	PermiteMDTypes when is_list(PermiteMDTypes) ->
	    suggest_chap(PermiteMDTypes)
    end.

suggest_chap([]) ->
    [];
suggest_chap([MDType|_]) ->
    {auth, chap, MDType}.

process_reqcis(Options, RejectIfDisagree, AllowedOpts, GotOpts) ->
    process_reqcis(Options, RejectIfDisagree, AllowedOpts, GotOpts, #lcp_opts{}, [], [], []).

process_reqcis([], _RejectIfDisagree, _AllowedOpts, _GotOpts, HisOpts, AckReply, NackReply, RejReply) ->
    Reply = if
		length(RejReply) /= 0 -> {rej, RejReply};
		length(NackReply) /= 0 -> {nack, NackReply};
		true -> {ack, AckReply}
	    end,
    {Reply, HisOpts};

process_reqcis([Opt|Options], RejectIfDisagree, AllowedOpts, GotOpts, HisOpts, AckReply, NAckReply, RejReply) ->
    {Verdict, HisOptsNew} = lcp_reqci(Opt, AllowedOpts, GotOpts, HisOpts),
    case Verdict of
	ack ->
	    process_reqcis(Options, RejectIfDisagree, AllowedOpts, GotOpts, HisOptsNew, [Opt|AckReply], NAckReply, RejReply);
	{nack, _} when RejectIfDisagree ->
	    process_reqcis(Options, RejectIfDisagree, AllowedOpts, GotOpts, HisOptsNew, AckReply, NAckReply, [Opt|RejReply]);
	{nack, NewOpt} ->
	    process_reqcis(Options, RejectIfDisagree, AllowedOpts, GotOpts, HisOptsNew, AckReply, [NewOpt|NAckReply], RejReply);
	rej ->
	    process_reqcis(Options, RejectIfDisagree, AllowedOpts, GotOpts, HisOptsNew, AckReply, NAckReply, [Opt|RejReply])
    end.
    
%%===================================================================
%% Event Processor
handle_configure_request(Id, Options, State = #state{got_opts = GotOpts, allow_opts = AllowedOpts}) ->
    NackCount = get_counter('Configure-Nak', State),
    {{Verdict, ReplyOpts}, HisOpts} = process_reqcis(Options, NackCount == 0, AllowedOpts, GotOpts),
    ReplyOpts1 = lists:reverse(ReplyOpts),
    NewState0 = State#state{his_opts = HisOpts},
    NewState1 = case Verdict of
		   nack -> 
			send_configure_nak(Id, ReplyOpts1, NewState0);
		   ack ->
			send_configure_ack(Id, ReplyOpts1, NewState0);
		   rej ->
			send_configure_reject(Id, ReplyOpts1, NewState0)
	       end,
    {Verdict, NewState1}.

handle_configure_ack(Id, Options, State = #state{reqid = Id, got_opts = GotOpts}) ->
    case lcp_ackcis(Options, GotOpts) of
	true -> State;
	Other -> Other
    end;

handle_configure_ack(_, _, _) ->
    %% invalid Id -> toss...
    false.

handle_configure_nak(DoUpdate, Id, Options, State = #state{reqid = Id, got_opts = GotOpts, want_opts = WantOpts}) ->
    case lcp_nakcis(Options, GotOpts, WantOpts, GotOpts, #lcp_opts{}) of
	TryOpts when is_record(TryOpts, lcp_opts) ->
	    if
		DoUpdate -> State#state{got_opts = TryOpts};
		true     -> State
	    end;
	Other -> Other
    end;

handle_configure_nak(_, Id, _, _) ->
    %% invalid Id -> toss...
    io:format("Invalid Id: ~p~n", [Id]),
    false.

handle_configure_rej(DoUpdate, Id, Options, State = #state{reqid = Id, got_opts = GotOpts}) ->
    case lcp_rejcis(Options, GotOpts, GotOpts) of
	TryOpts when is_record(TryOpts, lcp_opts) ->
	    if
		DoUpdate -> State#state{got_opts = TryOpts};
		true     -> State
	    end;
	Other -> Other
    end;

handle_configure_rej(_, _, _, _) ->
    %% invalid Id -> toss...
    false.

resetci(State = #state{want_opts = WantOpts}) ->
    WantOpts1 = WantOpts#lcp_opts{magicnumber = random:uniform(16#ffffffff)},
    NewState = State#state{want_opts = WantOpts1, got_opts = WantOpts1},
    auth_reset(NewState).

auth_reset(State = #state{got_opts = GotOpts}) ->
%% TODO:
%%   select auth schemes based on availabe secrets and config
%%
    GotOpts1 = GotOpts#lcp_opts{neg_auth = [eap, {chap, ?CHAP_ALL_AUTH}, pap]},
    State#state{got_opts = GotOpts1}.

send_configure_request(Retransmit, State = #state{reqid = Id, got_opts = GotOpts}) ->
    if Retransmit ->
	    NewId = Id;
       true ->
	    NewId = Id + 1
    end,
    Options = lcp_addcis(GotOpts),
    send_configure_request(Options, NewId, State#state{reqid = NewId}).

%%===================================================================
%% FSM Actions:
%%   tlu = This-Layer-Up
%%   tld = This-Layer-Down
%%   tls = This-Layer-Started
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

this_layer_up(State = #state{link = Link}) ->
    ppp_link:this_layer_up(Link, lcp),
    State.

this_layer_down(State = #state{link = Link}) ->
    ppp_link:this_layer_down(Link, lcp),
    State.

this_layer_started(State = #state{link = Link}) ->
    ppp_link:this_layer_started(Link, lcp),
    State.

%% TODO: we might want to terminate the FSM here...????
this_layer_finished(State = #state{link = Link}) ->
    ppp_link:this_layer_finished(Link, lcp),
    State.

%% TODO: count and period initial value from config....
initialize_restart_count(State = #state{config = Config}) ->
    State#state{term_restart_count = proplists:get_value(lcp_max_terminate, Config, 2),
		conf_restart_count = proplists:get_value(lcp_max_configure, Config, 10),
		failure_count = proplists:get_value(lcp_max_failure, Config, 5),
		restart_timeout = proplists:get_value(lcp_restart, Config, 3000)}.

%% initialize_failure_count(State = #state{config = Config}) ->
%%     State#state{failure_count = proplists:get_value(lcp_max_failure, Config, 5)}.

zero_restart_count(State = #state{config = Config}) ->
    State#state{term_restart_count = 0,
		conf_restart_count = 0,
		failure_count = 0,
		restart_timeout = proplists:get_value(lcp_restart, Config, 3000)}.

rearm_timer(State = #state{timer = Timer, restart_timeout = Timeout}) ->
    if is_reference(Timer) -> gen_fsm:cancel_timer(Timer);
       true -> ok
    end,
    State#state{timer = gen_fsm:start_timer(Timeout, timeout)}.
 
stop_timer(State = #state{timer = Timer}) ->
    if is_reference(Timer) -> gen_fsm:cancel_timer(Timer);
       true -> ok
    end,
    State#state{timer = undefined}.

send_configure_request(Options, Id, State) ->
    NewState0 = rearm_timer(State),
    NewState1 = NewState0#state{last_request = 'Configure-Request'},
    send_packet({lcp, 'CP-Configure-Request', Id, Options}, NewState1).

send_configure_ack(Id, Options, State) ->
    send_packet({lcp, 'CP-Configure-Ack', Id, Options}, State).

send_configure_nak(Id, Options, State) ->
    NewState = send_packet({lcp, 'CP-Configure-Nak', Id, Options}, State),
    dec_counter('Configure-Nak', NewState).

send_configure_reject(Id, Options, State) ->
    send_packet({lcp, 'CP-Configure-Reject', Id, Options}, State).

send_terminate_request(Data, State = #state{reqid = Id}) ->
    NewState0 = rearm_timer(State),
    NewState1 = NewState0#state{last_request = 'Terminate-Request'},
    send_packet({lcp, 'CP-Terminate-Request', Id + 1, Data}, NewState1#state{reqid = Id + 1}).

send_terminate_ack(Id, Data, State) ->
    send_packet({lcp, 'CP-Terminate-Ack', Id, Data}, State).

send_code_reject(Request, State) ->
    send_packet({lcp, 'CP-Code-Reject', element(3, Request), Request}, State).

send_echo_reply(Id, Data, State) ->
    send_packet({lcp, 'CP-Echo-Reply', Id, Data}, State).
