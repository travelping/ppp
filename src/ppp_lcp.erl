%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

-module(ppp_lcp).

-behaviour(ppp_fsm).
-behaviour(ppp_proto).

%% API
-export([start_link/3]).
-export([frame_in/2, lowerup/1, lowerdown/1, loweropen/1, lowerclose/2, protocol_reject/2]).

%% ppp_fsm callbacks
-export([init/2, up/1, down/1, starting/1, finished/1]).
-export([resetci/1, addci/2, ackci/3, nakci/4, rejci/3, reqci/4]).
-export([handler_lower_event/3]).
-export([opened/2, opened/3]).

-include("ppp_fsm.hrl").
-include("ppp_lcp.hrl").

-define(PROTOCOL, lcp).

-define(MINMRU, 128).
-define(MAXMRU, 1500).
-define(DEFMRU, 1500).
-define(PPP_LQR, 16#c025).
-define(CBCP_OPT, 6).
-define(CHAP_ALL_AUTH, {chap, 'MS-CHAP-v2'}, {chap, 'MS-CHAP'}, {chap, md5}).
-define(ALL_AUTH, [eap, ?CHAP_ALL_AUTH, pap]).

-record(state, {
	  config			:: list(),
	  %% passive = false		:: boolean(),			%% Don't die if we don't get a response
	  %% silent = true			:: boolean(),			%% Wait for the other end to start first
	  %% restart = false		:: boolean(),			%% Restart vs. exit after close

	  link				:: pid(),

	  want_opts			:: #lcp_opts{},			%% Options that we want to request
	  got_opts			:: #lcp_opts{}, 		%% Options that peer ack'd
	  allow_opts			:: #lcp_opts{},			%% Options we allow peer to request
	  his_opts			:: #lcp_opts{},			%% Options that we ack'd

	  echo_interval			:: integer(),
	  echo_failure			:: integer(),

	  echo_failure_count		:: integer(),
	  timer
	 }).

%%%===================================================================
%%% Protocol API
%%%===================================================================

start_link(Link, _Session, Config) ->
    ppp_fsm:start_link(Link, Config, ?MODULE).

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

protocol_reject(FSM, Request) ->
    ppp_fsm:send_event(FSM, {protocol_reject, Request}).
    
%%===================================================================
%% ppp_fsm callbacks
%%===================================================================

%% fsm events

handler_lower_event(Event, FSMState, State) ->
    %% do somthing
    ppp_fsm:handler_lower_event(Event, FSMState, State).


%% add a term to a List if Config Property is true
if_set(Property, Config, Term) ->
    case proplists:get_bool(Property, Config) of
	true -> Term;
	_ -> []
    end.

%% return a term if Config Property is not false
if_notfalse(Property, Config, Term) ->
    case proplists:get_value(Property, Config, true) of
	false -> Term;
	_ -> []
    end.

%% return boolean from proplist,
%% default to Default if not set
get_bool(Property, Config, Default) ->
    case proplists:get_value(Property, Config, Default) of
	true -> true;
	_    -> false
    end.

%% return false if a property matches a Value
false_if_equal(Property, Config, Value) ->
    case proplists:get_value(Property, Config) of
	Value -> false;
	_ ->     true
    end.

get_mru_bool(Config) ->
    case proplists:get_value(mru, Config, true) of
	Value when is_integer(Value) ->
	    true;
	true ->
	    true;
	_ -> false
    end.

get_mru_value(Config, Default) ->
    case proplists:get_value(mru, Config) of
	Value when is_integer(Value) ->
	    Value;
	_ -> Default
    end.

get_multilink_bool(MultiLink, _Property, _Config)
  when MultiLink =:= false ->
    false;
get_multilink_bool(_MultiLink, Property, Config) ->
    proplists:get_bool(Property, Config).

get_endpoint_bool(MultiLink, _Config, _Default)
  when MultiLink =:= false ->
    false;
get_endpoint_bool(_MultiLink, Config, Default) ->
    case proplists:get_value(endpoint, Config, Default) of
	{Class, Addr} when is_integer(Class), is_binary(Addr) ->
	    true;
	true ->
	    true;
	_ ->
	    false
    end.

get_endpoint_value(MultiLink, _Config)
  when MultiLink =:= false ->
    undefined;
get_endpoint_value(_MultiLink, Config) ->
    case proplists:get_value(endpoint, Config) of
	{Class, Addr} when is_integer(Class), is_binary(Addr) ->
	    #epdisc{class = Class, address = Addr};
	_ ->
	    #epdisc{}
    end.

%% fsm callback
%%
%% Options Processing:
%% (general proplists rules apply)
%%
%% Multi-Value Options:
%%
%%  Every options can have three possible value:
%%   true   -> will option try to negotiate
%%   false  -> will not attempt to negotiate but accept from peer
%%   reject -> will not attempt to negotiate and reject from peer
%%
%%   Options:
%%     asyncmap
%%
%%   Authentication Options:
%%    eap
%%    mschap_v2
%%    mschap
%%    chap
%%    pap
%%
%%  Special Multi-Value Options
%%    mru          -> use numeric value for mru instead of true! 
%%    endpoint     -> {Class, Address} tuple instead of true
%%
%% Enable/Disable (true/false) Options:
%%    pcomp
%%    accomp
%%    magic
%%    multilink    -> disable multilink negotiation
%%
init(Link, Config) ->
    %% Permit all AuthMechs that are not explicitly denied
    PermitedAuth = lists:flatten([if_notfalse(eap,       Config, eap),
				  if_notfalse(mschap_v2, Config, {chap, 'MS-CHAP-v2'}),
				  if_notfalse(mschap,    Config, {chap, 'MS-CHAP'}),
				  if_notfalse(chap,      Config, {chap, md5}),
				  if_notfalse(pap,       Config, pap)]),

    %% Want all AuthMechs that are explicitly requested
    WantAuth = lists:flatten([if_set(eap,       Config, eap),
			      if_set(mschap_v2, Config, {chap, 'MS-CHAP-v2'}),
			      if_set(mschap,    Config, {chap, 'MS-CHAP'}),
			      if_set(chap,      Config, {chap, md5}),
			      if_set(pap,       Config, pap)]),

    MultiLink = proplists:get_bool(multilink, Config),

    WantOpts = #lcp_opts{
      neg_mru = get_mru_bool(Config),
      mru = get_mru_value(Config, ?DEFMRU),
      neg_asyncmap = get_bool(asyncmap, Config, true),
      neg_auth = WantAuth,
      neg_magicnumber = get_bool(magic, Config, true),
      neg_pcompression = get_bool(pcomp, Config, true),
      neg_accompression = get_bool(accomp, Config, true),

      neg_mrru = get_multilink_bool(MultiLink, mrru, Config),
      neg_ssnhf = get_multilink_bool(MultiLink, shortseq, Config),

      neg_endpoint = get_endpoint_bool(MultiLink, Config, false),
      endpoint = get_endpoint_value(MultiLink, Config)
     },

    AllowOpts = #lcp_opts{
      neg_mru = get_mru_bool(Config),
      mru = get_mru_value(Config, ?MAXMRU),
      neg_asyncmap = false_if_equal(asyncmap, Config, reject),
      neg_auth = PermitedAuth,
      neg_magicnumber = get_bool(magic, Config, true),
      neg_pcompression = false_if_equal(pcomp, Config, reject),
      neg_accompression = false_if_equal(accomp, Config, reject),

      neg_mrru = get_multilink_bool(MultiLink, mrru, Config),
      neg_ssnhf = get_multilink_bool(MultiLink, shortseq, Config),
      neg_endpoint = get_endpoint_bool(MultiLink, Config, true)
     },

%% TODO: apply config to want_opts and allow_opts

    FsmConfig = #fsm_config{
      passive = proplists:get_bool(passive, Config),
      silent = proplists:get_bool(silent, Config),
%%      restart = proplists:get_bool(restart, Config),

      term_restart_count = proplists:get_value(lcp_max_terminate, Config, 2),
      conf_restart_count = proplists:get_value(lcp_max_configure, Config, 10),
      failure_count = proplists:get_value(lcp_max_failure, Config, 5),
      restart_timeout = proplists:get_value(lcp_restart, Config, 3000)
     },

    {ok, ?PROTOCOL, FsmConfig, #state{link = Link, config = Config,
				      want_opts = WantOpts, allow_opts = AllowOpts,
				      echo_interval = proplists:get_value(lcp_echo_interval, Config, 60000),
				      echo_failure = proplists:get_value(lcp_echo_failure, Config, 3)
				     }}.

resetci(State = #state{want_opts = WantOpts}) ->
    WantOpts1 = WantOpts#lcp_opts{magicnumber = rand:uniform(16#ffffffff)},
    NewState = State#state{want_opts = WantOpts1, got_opts = WantOpts1},
    auth_reset(NewState).

auth_reset(State = #state{got_opts = GotOpts}) ->
%% TODO:
%%   select auth schemes based on availabe secrets and config
%%
    State#state{got_opts = GotOpts}.

addci(_StateName, State = #state{got_opts = GotOpts}) ->
    Options = lcp_addcis(GotOpts),
    {Options, State}.

ackci(_StateName, Options, State = #state{got_opts = GotOpts}) ->
    Reply = lcp_ackcis(Options, GotOpts),
    {Reply, State}.

nakci(StateName, Options, _TreatAsReject,
      State = #state{got_opts = GotOpts, want_opts = WantOpts}) ->
    DoUpdate = StateName /= opened,
    case lcp_nakcis(Options, GotOpts, WantOpts, GotOpts, #lcp_opts{}) of
	TryOpts when is_record(TryOpts, lcp_opts) ->
	    if
		DoUpdate -> {true, State#state{got_opts = TryOpts}};
		true     -> {true, State}
	    end;
	Other -> {false, Other}
    end.

rejci(StateName, Options, State = #state{got_opts = GotOpts}) ->
    DoUpdate = StateName /= opened,
    case lcp_rejcis(Options, GotOpts, GotOpts) of
	TryOpts when is_record(TryOpts, lcp_opts) ->
	    if
		DoUpdate -> {true, State#state{got_opts = TryOpts}};
		true     -> {true, State}
	    end;
	Other -> {false, Other}
    end.

reqci(_StateName, Options, RejectIfDisagree,
      State = #state{got_opts = GotOpts, allow_opts = AllowedOpts}) ->
    {{Verdict, ReplyOpts}, HisOpts} = process_reqcis(Options, RejectIfDisagree, AllowedOpts, GotOpts),
    ReplyOpts1 = lists:reverse(ReplyOpts),
    NewState = State#state{his_opts = HisOpts},
    {{Verdict, ReplyOpts1}, NewState}.

up(State = #state{got_opts = GotOpts,
		  his_opts = HisOpts,
		  echo_interval = EchoInterval,
		  echo_failure = EchoFailure}) ->
    lager:debug("~p: Up", [?MODULE]),
    %% Link is ready,
    %% set MRU, MMRU, ASyncMap and Compression options on Link
    %% Set Link Up

    %% Enable LCP Echos
    NewState = if
		   EchoInterval > 0 ->
		       NewState0 = State#state{echo_failure_count = EchoFailure},
		       rearm_timer(request_echo, EchoInterval, NewState0);
		   true ->
		       State
	       end,

    Reply = {up, GotOpts, HisOpts},
    {Reply, NewState}.

down(State) ->
    lager:debug("~p: Down", [?MODULE]),

    %% Disable LCP Echos
    NewState = stop_timer(State),

    %% Set Link Down
    {down, NewState}.

starting(State) ->
    lager:debug("~p: Starting", [?MODULE]),
    %%link_required(f->unit);
    {starting, State}.


finished(State) ->
    lager:debug("~p: Finished", [?MODULE]),
    %% link_terminated(f->unit);
    {terminated, State}.

%%===================================================================
%% ppp_fsm state callbacks
%%===================================================================
opened({timeout, _Ref, request_echo}, ReqId,
       State = #state{
		  got_opts = GotOpts,
		  echo_interval = EchoInterval,
		  echo_failure_count = Cnt}) ->
    case Cnt of
	_ when Cnt > 0 ->
	    NewState0 = State#state{echo_failure_count = Cnt - 1},
	    NewState1 = rearm_timer(request_echo, EchoInterval, NewState0),

	    NewReqId = ReqId + 1,
	    Request = {?PROTOCOL, 'CP-Echo-Request', NewReqId, GotOpts#lcp_opts.magicnumber},
	    {send, Request, NewReqId, opened, NewState1};
	0 ->
	    lager:debug("~p: Echo-Request Timeout, closing", [?MODULE]),
	    {close, <<"Peer not responding">>, State}
    end;

opened({protocol_reject, Request}, ReqId, State) ->
    Protocol = element(1, Request),
    <<_:16, BinRequest/binary>> = ppp_frame:encode(Request),
    NewReqId = ReqId + 1,
    SendReq = {?PROTOCOL, 'CP-Protocol-Reject', NewReqId, Protocol, BinRequest},
    {send, SendReq, NewReqId, opened, State}.

opened({_, 'CP-Echo-Reply', _Id, Magic}, State =
	   #state{his_opts = HisOpts,
		  echo_interval = EchoInterval,
		  echo_failure = EchoFailure})
  when Magic =:= HisOpts#lcp_opts.magicnumber ->
    NewState0 = State#state{echo_failure_count = EchoFailure},
    NewState1 = rearm_timer(request_echo, EchoInterval, NewState0),
    {ok, opened, NewState1};

opened({_, 'CP-Echo-Reply', _Id, Magic}, State = #state{his_opts = HisOpts}) ->
    lager:debug("got echo-reply with invaid magic, got ~p, expected ~p",
	      [Magic, HisOpts#lcp_opts.magicnumber]),
    {ignore, opened, State};

opened({_, 'CP-Echo-Request', Id, Magic}, State = #state{got_opts = GotOpts, his_opts = HisOpts})
  when Magic =:= HisOpts#lcp_opts.magicnumber ->
    Reply = {?PROTOCOL, 'CP-Echo-Reply', Id, GotOpts#lcp_opts.magicnumber},
    {send_reply, opened, Reply, State};

opened({_, 'CP-Echo-Request', _Id, Magic}, State = #state{his_opts = HisOpts}) ->
    lager:debug("got echo-request with invaid magic, got ~p, expected ~p",
	      [Magic, HisOpts#lcp_opts.magicnumber]),
    {ignore, opened, State};

opened(_, State) ->
    {ignore, opened, State}.

%%===================================================================

cancel_timer(Ref) ->
    case erlang:cancel_timer(Ref) of
	false ->
	    receive {timeout, Ref, _} -> 0
	    after 0 -> false
	    end;
	RemainingTime ->
	    RemainingTime
    end.

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
    lager:debug("lcp_addci: skiping auth: ~p", [GotAuth]),
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
lcp_nakci({auth, NakAuth}, #lcp_opts{neg_auth = []}, _WantOpts, TryOpts, NakOpts = #lcp_opts{neg_auth = []}) ->
    N1 = NakOpts#lcp_opts{neg_auth = NakOpts#lcp_opts.neg_auth ++ NakAuth},
    {TryOpts, N1};

lcp_nakci({auth, NakAuth}, #lcp_opts{neg_auth = GotAuth}, _WantOpts, TryOpts, NakOpts) ->
    case GotAuth of
	[NakAuth|_] ->
	    %% Whoops, they Nak'd our algorithm of choice
	    %% but then suggested it back to us.
	    false;
	[LastAuth|TryAuth] ->
	    T1 = TryOpts#lcp_opts{neg_auth = TryAuth},
	    lager:debug("neg_auth: ~p", [NakOpts#lcp_opts.neg_auth]),
	    lager:debug("NakAuth: ~p", [NakAuth]),
	    N1 = NakOpts#lcp_opts{neg_auth = NakOpts#lcp_opts.neg_auth ++ [LastAuth]},
	    {T1, N1}
    end;

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
    T1 = TryOpts#lcp_opts{magicnumber = rand:uniform(16#ffffffff)},
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

%%TODO: does this really matter?
%%
%% RFC1661 says:
%%   Options from the Configure-Request MUST NOT be reordered
%% we do not enforce ordering here, pppd does
%%
%% Note: on generating Ack/Naks we do preserve ordering!
%%
lcp_nakcis([], _, _, TryOpts, _) ->
    lager:debug("lcp_nakcis: ~p", [TryOpts]),
    TryOpts;
lcp_nakcis([Opt|Options], GotOpts, WantOpts, TryOpts, NakOpts) ->
    case lcp_nakci(Opt, GotOpts, WantOpts, TryOpts, NakOpts) of
	{NewTryOpts, NewNakOpts} ->
	    lcp_nakcis(Options, GotOpts, WantOpts, NewTryOpts, NewNakOpts);
	_ ->
	    lager:debug("lcp_nakcis: received bad Nakt!"),
	    false
    end.

-spec lcp_rejci(RejOpt :: ppp_option(),
		GotOpts :: #lcp_opts{},
		TryOpts :: #lcp_opts{}) -> #lcp_opts{}.

lcp_rejci({mru, MRU}, #lcp_opts{neg_mru = true, mru = MRU}, TryOpts) ->
    TryOpts#lcp_opts{neg_mru = false};

lcp_rejci({asyncmap, ACCM}, #lcp_opts{neg_asyncmap = true, asyncmap = ACCM}, TryOpts) ->
    TryOpts#lcp_opts{neg_asyncmap = false};

lcp_rejci({auth, RejAuth}, #lcp_opts{neg_auth = GotAuth}, TryOpts = #lcp_opts{neg_auth = TryAuth}) ->
    case lists:member(RejAuth, GotAuth) of
	true -> TryOpts#lcp_opts{neg_auth = lists:delete(RejAuth, TryAuth)};
	_    -> false
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
    lager:debug("acfs rejected"),
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
	    lager:debug("lcp_rejcis: received bad Reject!"),
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
    
lcp_ackci({auth, AckAuth}, #lcp_opts{neg_auth = GotAuth}) ->
    lager:debug("AckAuth: ~p", [AckAuth]),
    lager:debug("GotAuth: ~p", [GotAuth]),
    lists:member(AckAuth, GotAuth);

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
    lager:debug("invalid Ack: ~p", [Ack]),
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
	    lager:debug("lcp_ackcis: received bad Ack! ~p, ~p", [AckOpt, GotOpts]),
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

lcp_reqci({auth, _}, #lcp_opts{neg_auth = PermitedAuth}, _, HisOpts)
  when not is_list(PermitedAuth) orelse PermitedAuth == [] ->
    lager:debug("No auth is possible"),
    {rej, HisOpts};

%% Authtype must be PAP, CHAP, or EAP.
%%
%% Note: if more than one of ao->neg_upap, ao->neg_chap, and
%% ao->neg_eap are set, and the peer sends a Configure-Request
%% with two or more authenticate-protocol requests, then we will
%% reject the second request.
%% Whether we end up doing CHAP, UPAP, or EAP depends then on
%% the ordering of the CIs in the peer's Configure-Request.

lcp_reqci({auth, ReqAuth}, _, _, HisOpts = #lcp_opts{neg_auth = HisAuth})
  when HisAuth /= none ->
    lager:debug("lcp_reqci: rcvd AUTHTYPE ~p, rejecting...", [ReqAuth]),
    {rej, HisOpts};
lcp_reqci({auth, ReqAuth}, #lcp_opts{neg_auth = PermitedAuth}, _, HisOpts) ->
    case lists:member(ReqAuth, PermitedAuth) of
	true ->
	    Verdict = ack,
	    HisOptsNew = HisOpts#lcp_opts{neg_auth = ReqAuth};
	_ ->
	    Verdict = {nack, suggest_auth(PermitedAuth)},
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
	    Verdict = {rej, {magic, rand:uniform(16#ffffffff)}},
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
    lager:debug("lcp_reqci: rejecting: ~p", [Req]),
    lager:debug("His: ~p", [HisOpts]),
    {rej, HisOpts}.

%% take the first element that is present in both lists
suggest_auth(PermitedAuths) ->
    suggest_auth(PermitedAuths, ?ALL_AUTH).
suggest_auth(_, []) ->
    [];
suggest_auth(PermitedAuths, [Auth|Rest]) ->
    case lists:member(Auth, PermitedAuths) of
	false ->
	    suggest_auth(PermitedAuths, Rest);
	true ->
	    {auth, Auth}
    end.

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
