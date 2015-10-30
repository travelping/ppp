%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

-module(ppp_ipv6cp).

-behaviour(ppp_fsm).
-behaviour(ppp_proto).

%% API
-export([start_link/2]).
-export([frame_in/2, lowerup/1, lowerdown/1, loweropen/1, lowerclose/2]).

%% ppp_fsm callbacks
-export([init/2, up/1, down/1, starting/1, finished/1]).
-export([resetci/1, addci/2, ackci/3, nakci/4, rejci/3, reqci/4]).
-export([handler_lower_event/3]).

-include("ppp_fsm.hrl").
-include("ppp_ipv6cp.hrl").

-record(state, {
	  config			:: list(),
	  link				:: pid(),

	  want_opts			:: #ipv6cp_opts{},		%% Options that we want to request
	  got_opts			:: #ipv6cp_opts{}, 		%% Options that peer ack'd
	  allow_opts			:: #ipv6cp_opts{},		%% Options we allow peer to request
	  his_opts			:: #ipv6cp_opts{}			%% Options that we ack'd
	 }).

-define(IPCP_VJC_COMP,   16#2d).	%% Van Jacobson Compressed TCP/IP		[RFC1144][RFC1332]
-define(IPCP_IPH_COMP,   16#61).	%% Robust Header Compression (ROHC) 		[RFC3241]
-define(IPCP_ROG_COMP,   16#03).	%% IP Header Compression			[RFC2507][RFC3544]

-define(MAX_STATES, 16).

%%%===================================================================
%%% Protocol API
%%%===================================================================

start_link(Link, Config) ->
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

%%===================================================================
%% ppp_fsm callbacks
%%===================================================================

%% fsm events

handler_lower_event(Event, FSMState, State) ->
    %% do somthing
    ppp_fsm:handler_lower_event(Event, FSMState, State).

opt_get_bool(Key, List, Default) ->
    case proplists:get_value(Key, List) of
	undefined -> Default;
	true      -> true;
	_         -> false
    end.

init(Link, Config) ->
    State0 = #state{link = Link, config = Config},
    State1 = init_opts(State0),

    FsmConfig = #fsm_config{
      passive = proplists:get_bool(passive, Config),
      silent = proplists:get_bool(silent, Config),
%%      restart = proplists:get_bool(restart, Config),
      term_restart_count = proplists:get_value(ipv6cp_max_terminate, Config, 2),
      conf_restart_count = proplists:get_value(ipv6cp_max_configure, Config, 10),
      failure_count = proplists:get_value(ipv6cp_max_failure, Config, 5),
      restart_timeout = proplists:get_value(ipv6cp_restart, Config, 3000)
     },

    {ok, ipv6cp, FsmConfig, State1}.

init_opts(State = #state{config = Config}) ->
    WantOpts = #ipv6cp_opts{
      neg_ifaceid = true,
      accept_local = proplists:get_bool(accept_local, Config),
      neg_vj = opt_get_bool(vj, Config, false),
      vj_protocol = ipv6_hc,

      ourid = proplists:get_value(ipv6cp_ourid, Config, <<0:64>>),
      hisid = proplists:get_value(ipv6cp_hisid, Config, <<0:64>>)
     },

    AllowOpts = #ipv6cp_opts{
      neg_ifaceid = true,
      neg_vj = opt_get_bool(vj, Config, true),

      ourid = proplists:get_value(ipv6cp_ourid, Config, <<0:64>>)
     },

    State#state{want_opts = WantOpts, allow_opts = AllowOpts}.

%% fsm callback
resetci(State = #state{want_opts = WantOpts, allow_opts = AllowOpts}) ->
    WantOpts1 = WantOpts#ipv6cp_opts{
		  req_ifaceid = (WantOpts#ipv6cp_opts.neg_ifaceid and AllowOpts#ipv6cp_opts.neg_ifaceid),
		  accept_local = (WantOpts#ipv6cp_opts.ourid == <<0:64>>),
		  ourid = iface_magic(AllowOpts#ipv6cp_opts.ourid, <<0:64>>)
		 },
    State#state{want_opts = WantOpts1, got_opts = WantOpts1#ipv6cp_opts{hisid = <<0:64>>}}.

addci(_StateName, State = #state{got_opts = GotOpts}) ->
    Options = ipv6cp_addcis(GotOpts),
    {Options, State}.

ackci(_StateName, Options, State = #state{got_opts = GotOpts}) ->
    Reply = ipv6cp_ackcis(Options, GotOpts),
    {Reply, State}.

nakci(StateName, Options, TreatAsReject,
      State = #state{got_opts = GotOpts}) ->
    DoUpdate = StateName /= opened,
    case ipv6cp_nakcis(Options, TreatAsReject, GotOpts, GotOpts, #ipv6cp_opts{}) of
	TryOpts when is_record(TryOpts, ipv6cp_opts) ->
	    if
		DoUpdate -> {true, State#state{got_opts = TryOpts}};
		true     -> {true, State}
	    end;
	Other -> {false, Other}
    end.

rejci(StateName, Options, State = #state{got_opts = GotOpts}) ->
    DoUpdate = StateName /= opened,
    case ipv6cp_rejcis(Options, GotOpts, GotOpts) of
	TryOpts when is_record(TryOpts, ipv6cp_opts) ->
	    if
		DoUpdate -> {true, State#state{got_opts = TryOpts}};
		true     -> {true, State}
	    end;
	Other -> {false, Other}
    end.

reqci(_StateName, Options, RejectIfDisagree,
      State = #state{want_opts = WantOpts,
		     got_opts = GotOpts,
		     allow_opts = AllowedOpts}) ->
    {{Verdict, ReplyOpts}, WantOptsNew, GotOptsNew, HisOpts} =
	process_reqcis(Options, RejectIfDisagree, AllowedOpts, WantOpts, GotOpts),
    ReplyOpts1 = lists:reverse(ReplyOpts),
    NewState = State#state{want_opts = WantOptsNew, got_opts = GotOptsNew, his_opts = HisOpts},
    {{Verdict, ReplyOpts1}, NewState}.

up(State) ->
    io:format("~p: Up~n", [?MODULE]),
    up_validate_neg_ifaceid(State).

up_validate_neg_ifaceid(State = #state{
		       want_opts = WantOpts,
		       got_opts = GotOpts,
		       his_opts = HisOpts0}) ->
    HisOpts1 = if not HisOpts0#ipv6cp_opts.neg_ifaceid ->
		       HisOpts0#ipv6cp_opts{hisid = WantOpts#ipv6cp_opts.hisid};
		  true ->
		       HisOpts0
	       end,

    if 
       GotOpts#ipv6cp_opts.ourid == <<0:64>> ->
	    Reply = {close, <<"Could not determine local LL address">>},
	    {Reply, State};

       HisOpts1#ipv6cp_opts.hisid == <<0:64>> ->
	    Reply = {close, <<"Could not determine remote LL address">>},
	    {Reply, State};

       GotOpts#ipv6cp_opts.ourid == HisOpts1#ipv6cp_opts.hisid ->
	    Reply = {close, <<"local and remote LL addresses are equal">>},
	    {Reply, State};

       true ->
	   NewState = State#state{his_opts = HisOpts1},
	    Reply = {up, GotOpts, HisOpts1},
	    {Reply, NewState}
    end.

down(State) ->
    io:format("~p: Down~n", [?MODULE]),
    %% Disable IPCP Echos
    %% Set Link Down
    {down, State}.

starting(State) ->
    io:format("~p: Starting~n", [?MODULE]),
    %%link_required(f->unit);
    {starting, State}.


finished(State) ->
    io:format("~p: Finished~n", [?MODULE]),
    %% link_terminated(f->unit);
    {terminated, State}.

%%===================================================================
%% Option Generation
-define(IPV6CP_OPTS, [compresstype, ifaceid]).

-spec ipv6cp_addci(AddOpt :: atom(),
		 GotOpts :: #ipv6cp_opts{}) -> ppp_option().

ipv6cp_addci(compresstype, #ipv6cp_opts{neg_vj = true, vj_protocol = Proto}) ->
    {compresstype, Proto};

ipv6cp_addci(ifaceid, #ipv6cp_opts{neg_ifaceid = true, ourid = OurId}) ->
    {ifaceid, OurId};

ipv6cp_addci(_, _) ->
    [].

ipv6cp_addcis(GotOpts) ->
    [ipv6cp_addci(Opt, GotOpts) || Opt <- ?IPV6CP_OPTS].

%%===================================================================
%% Option Validations
-spec ipv6cp_nakci(NakOpt :: ppp_option(),
		 TreatAsReject :: boolean(),
		 GotOpts :: #ipv6cp_opts{},
		 TryOpts :: #ipv6cp_opts{},
		 NakOpts :: #ipv6cp_opts{}) -> {#ipv6cp_opts{}, #ipv6cp_opts{}}.


ipv6cp_nakci(NakOpt, true, #ipv6cp_opts{neg_vj = true}, TryOpts, NakOpts)
  when element(1, NakOpt) == compresstype ->
    T1 = TryOpts#ipv6cp_opts{neg_vj = false},
    N1 = NakOpts#ipv6cp_opts{neg_vj = true},
    {T1, N1};

ipv6cp_nakci({compresstype, ipv6_hc}, _,
	   #ipv6cp_opts{neg_vj = true}, TryOpts, NakOpts) ->
    T1 = TryOpts#ipv6cp_opts{neg_vj = false},
    N1 = NakOpts#ipv6cp_opts{neg_vj = true},
    {T1, N1};

ipv6cp_nakci(NakOpt, _,
	   #ipv6cp_opts{neg_vj = false}, TryOpts,
	   NakOpts = #ipv6cp_opts{neg_vj = false})
  when element(1, NakOpt) == compresstype ->
    N1 = NakOpts#ipv6cp_opts{neg_vj = true},
    {TryOpts, N1};

ipv6cp_nakci({ifaceid, _}, true, #ipv6cp_opts{neg_ifaceid = true},TryOpts, NakOpts) ->
    T1 = TryOpts#ipv6cp_opts{neg_ifaceid = false},
    N1 = NakOpts#ipv6cp_opts{neg_ifaceid = true},
    {T1, N1};

ipv6cp_nakci({ifaceid, NakOurId}, _, GotOpts = #ipv6cp_opts{neg_ifaceid = true},
	   TryOpts, NakOpts) ->
    T1 = if GotOpts#ipv6cp_opts.accept_local ->
		 OurId = iface_magic(NakOurId, GotOpts#ipv6cp_opts.hisid),
		 TryOpts#ipv6cp_opts{ourid = OurId};
	    true -> TryOpts
	 end,
    N1 = NakOpts#ipv6cp_opts{neg_ifaceid = true},
    {T1, N1};

ipv6cp_nakci({ifaceid, NakOurId}, _, GotOpts = #ipv6cp_opts{neg_ifaceid = false},
	   TryOpts, NakOpts = #ipv6cp_opts{neg_ifaceid = false}) ->
    T1 = if GotOpts#ipv6cp_opts.accept_local ->
		 OurId = iface_magic(NakOurId, GotOpts#ipv6cp_opts.hisid),
		 TryOpts#ipv6cp_opts{ourid = OurId};
	    true -> TryOpts
	 end,
    T2 = T1#ipv6cp_opts{neg_ifaceid = true},
    N1 = NakOpts#ipv6cp_opts{neg_ifaceid = true},
    {T2, N1};

ipv6cp_nakci(_, _, _, _, _) ->
    false.

%%TODO: does this really matter?
%%
%% RFC1661 says:
%%   Options from the Configure-Request MUST NOT be reordered
%% we do not enforce ordering here, pppd does
%%
%% Note: on generating Ack/Naks we do preserve ordering!
%%
ipv6cp_nakcis([], _TreatAsReject, _, TryOpts, _) ->
    io:format("ipv6cp_nakcis: ~p~n", [TryOpts]),
    TryOpts;
ipv6cp_nakcis([Opt|Options], TreatAsReject, GotOpts, TryOpts, NakOpts) ->
    case ipv6cp_nakci(Opt, TreatAsReject, GotOpts, TryOpts, NakOpts) of
	{NewTryOpts, NewNakOpts} ->
	    ipv6cp_nakcis(Options, TreatAsReject, GotOpts, NewTryOpts, NewNakOpts);
	_ ->
	    io:format("ipv6cp_nakcis: received bad Nakt!~n"),
	    false
    end.

-spec ipv6cp_rejci(RejOpt :: ppp_option(),
		 GotOpts :: #ipv6cp_opts{},
		 TryOpts :: #ipv6cp_opts{}) -> #ipv6cp_opts{}.

ipv6cp_rejci({compresstype, Proto},
	  #ipv6cp_opts{neg_vj = true, vj_protocol = Proto}, TryOpts) ->
    TryOpts#ipv6cp_opts{neg_vj = false};

ipv6cp_rejci({ifaceid, OurId}, #ipv6cp_opts{neg_ifaceid = true, ourid = OurId}, TryOpts) ->
    TryOpts#ipv6cp_opts{neg_ifaceid = false};

ipv6cp_rejci(_, _, _) ->
    false.

%%TODO: does this really matter?
%%
%% RFC1661 says:
%%   Options from the Configure-Request MUST NOT be reordered
%% we do not enforce ordering here, pppd does
%%
%% Note: on generating Ack/Naks we do preserve ordering!
%%
ipv6cp_rejcis([], _, TryOpts) ->
    TryOpts;
ipv6cp_rejcis([RejOpt|RejOpts], GotOpts, TryOpts) ->
    case ipv6cp_rejci(RejOpt, GotOpts, TryOpts) of
	NewTryOpts when is_record(NewTryOpts, ipv6cp_opts) ->
	    ipv6cp_rejcis(RejOpts, GotOpts, NewTryOpts);
	_ ->
	    io:format("ipv6cp_rejcis: received bad Reject!~n"),
	    false
    end.

-spec ipv6cp_ackci(AckOpt :: ppp_option(),
		 GotOpts :: #ipv6cp_opts{}) -> true | false.

ipv6cp_ackci({compresstype, Proto}, #ipv6cp_opts{neg_vj = true, vj_protocol = Proto}) ->
    true;

ipv6cp_ackci({ifaceid, OurId}, #ipv6cp_opts{neg_ifaceid = true, ourid = OurId}) ->
    true;

ipv6cp_ackci(Ack, _) ->
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
ipv6cp_ackcis([], _) ->
    true;
ipv6cp_ackcis([AckOpt|AckOpts], GotOpts) ->
    case ipv6cp_ackci(AckOpt, GotOpts) of
	false ->
	    io:format("ipv6cp_ackcis: received bad Ack! ~p, ~p~n", [AckOpt, GotOpts]),
	    false;
	_ ->
	    ipv6cp_ackcis(AckOpts, GotOpts)
    end.

-spec ipv6cp_reqci(ReqOpt :: ppp_option(),
		 AllowedOpts :: #ipv6cp_opts{},
		 WantOpts :: #ipv6cp_opts{},
		 GotOpts :: #ipv6cp_opts{},
		 HisOpts :: #ipv6cp_opts{}) ->
			{Verdict :: atom() | {atom() | ppp_option()},
			 GotOptsNew :: #ipv6cp_opts{},
			 HisOptsNew :: #ipv6cp_opts{}}.

ipv6cp_reqci({compresstype, Proto},
	    #ipv6cp_opts{neg_vj = true, vj_protocol = Proto}, _WantOpts, GotOpts, HisOpts) ->
    Verdict = ack,
    HisOptsNew = HisOpts#ipv6cp_opts{neg_vj = true, vj_protocol = Proto},
    {Verdict, GotOpts, HisOptsNew};
    
%% If he has no interface identifier, or if we both have same 
%% identifier then NAK it with new idea.
%% In particular, if we don't know his identifier, but he does,
%% then accept it.
ipv6cp_reqci({ifaceid, ReqHisId}, #ipv6cp_opts{neg_ifaceid = true}, WantOpts, GotOpts, HisOpts) ->
    if 
	(ReqHisId == <<0:64>>) and (GotOpts#ipv6cp_opts.ourid == <<0:64>>) ->
	    Verdict = rej,
	    HisOptsNew = HisOpts,
	    GotOptsNew = GotOpts;

	(WantOpts#ipv6cp_opts.hisid /= <<0:64>>) and
	(ReqHisId /= WantOpts#ipv6cp_opts.hisid) and
	(GotOpts#ipv6cp_opts.hisid == <<0:64>>) ->
	    Verdict = {nack, {ifaceid, WantOpts#ipv6cp_opts.hisid}},
	    HisOptsNew = HisOpts#ipv6cp_opts{neg_ifaceid = true, hisid = ReqHisId},
	    GotOptsNew = GotOpts#ipv6cp_opts{hisid = WantOpts#ipv6cp_opts.hisid};

	(ReqHisId == <<0:64>>) or (ReqHisId == GotOpts#ipv6cp_opts.ourid) ->
	    %% first time, try option
	    ReqHisId0 = if 
			    GotOpts#ipv6cp_opts.hisid == <<0:64>> ->
				WantOpts#ipv6cp_opts.hisid;
			    true ->
				ReqHisId
			end,
	    ReqHisId1 = iface_magic(ReqHisId0, GotOpts#ipv6cp_opts.ourid),
	    Verdict = {nack, {ifaceid, ReqHisId1}},
	    HisOptsNew = HisOpts#ipv6cp_opts{neg_ifaceid = true, hisid = ReqHisId1},
	    GotOptsNew = GotOpts#ipv6cp_opts{hisid = ReqHisId1};

	true ->
	    Verdict = ack,
	    HisOptsNew = HisOpts#ipv6cp_opts{neg_ifaceid = true, hisid = ReqHisId},
	    GotOptsNew = GotOpts
    end,
    {Verdict, GotOptsNew , HisOptsNew};

ipv6cp_reqci(Req, _, _WantOpts, GotOpts, HisOpts) ->
    io:format("lcp_reqci: rejecting: ~p~n", [Req]),
    io:format("His: ~p~n", [HisOpts]),
    {rej, GotOpts, HisOpts}.

process_reqcis(Options, RejectIfDisagree, AllowedOpts, WantOpts, GotOpts) ->
    process_reqcis(Options, RejectIfDisagree, AllowedOpts, WantOpts, GotOpts, #ipv6cp_opts{}, [], [], []).

process_reqcis([], _RejectIfDisagree, _AllowedOpts, WantOpts, GotOpts, HisOpts, _AckReply, _NackReply, RejReply)
  when length(RejReply) /= 0 ->
    Reply = {rej, RejReply},
    {Reply, WantOpts, GotOpts, HisOpts};

%% If we aren't rejecting this packet, and we want to negotiate
%% their identifier and they didn't send their identifier, then we
%% send a NAK with a CI_IFACEID option appended.  We assume the
%% input buffer is long enough that we can append the extra
%% option safely.
process_reqcis([], _RejectIfDisagree, _AllowedOpts, WantOpts, GotOpts, HisOpts, _AckReply, NackReply, _RejReply)
  when not HisOpts#ipv6cp_opts.neg_ifaceid and WantOpts#ipv6cp_opts.req_ifaceid ->
    if length(NackReply) /= 0 ->
	    NewWantOpts = WantOpts;
       true ->
	    NewWantOpts = WantOpts#ipv6cp_opts{req_ifaceid = false}     %% don't ask again
    end,
    Reply = {nack, [{ifaceid, WantOpts#ipv6cp_opts.hisid}|NackReply]},
    {Reply, NewWantOpts, GotOpts, HisOpts};
    
process_reqcis([], _RejectIfDisagree, _AllowedOpts, WantOpts, GotOpts, HisOpts, AckReply, NackReply, _RejReply) ->
    Reply = if
		length(NackReply) /= 0 -> {nack, NackReply};
		true -> {ack, AckReply}
	    end,
    {Reply, WantOpts, GotOpts, HisOpts};

process_reqcis([Opt|Options], RejectIfDisagree, AllowedOpts, WantOpts, GotOpts, HisOpts, AckReply, NAckReply, RejReply) ->
    {Verdict, GotOptsNew, HisOptsNew} = ipv6cp_reqci(Opt, AllowedOpts, WantOpts, GotOpts, HisOpts),
    case Verdict of
	ack ->
	    process_reqcis(Options, RejectIfDisagree, AllowedOpts, WantOpts, GotOptsNew, HisOptsNew, [Opt|AckReply], NAckReply, RejReply);
	{nack, _} when RejectIfDisagree ->
	    process_reqcis(Options, RejectIfDisagree, AllowedOpts, WantOpts, GotOptsNew, HisOptsNew, AckReply, NAckReply, [Opt|RejReply]);
	{nack, NewOpt} ->
	    process_reqcis(Options, RejectIfDisagree, AllowedOpts, WantOpts, GotOptsNew, HisOptsNew, AckReply, [NewOpt|NAckReply], RejReply);
	rej ->
	    process_reqcis(Options, RejectIfDisagree, AllowedOpts, WantOpts, GotOptsNew, HisOptsNew, AckReply, NAckReply, [Opt|RejReply])
    end.

%%===================================================================
%% internal helpers
%%===================================================================

iface_magic(IFaceId, Other)
  when IFaceId == <<0:64>>;
       IFaceId == Other->
    iface_magic(new_magic(), Other);
iface_magic(IFaceId, _) ->
    IFaceId.

new_magic() ->
    <<A:6, _:1, B:57>> = crypto:rand_bytes(8),
    <<A:6, 0:1, B:57>>.
