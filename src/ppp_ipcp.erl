%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

-module(ppp_ipcp).

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
-include("ppp_ipcp.hrl").

-record(state, {
	  config			:: list(),
	  link				:: pid(),

	  want_opts			:: #ipcp_opts{},		%% Options that we want to request
	  got_opts			:: #ipcp_opts{}, 		%% Options that peer ack'd
	  allow_opts			:: #ipcp_opts{},		%% Options we allow peer to request
	  his_opts			:: #ipcp_opts{}			%% Options that we ack'd
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

opt_vjslots(Config, State = #state{want_opts = WantOpts, allow_opts = AllowOpts}) ->
    case proplists:get_value(vj_max_slots, Config, ?MAX_STATES - 1) of
	Value when Value < ?MAX_STATES andalso Value >= 2 ->
	    State#state{
	      want_opts = WantOpts#ipcp_opts{maxslotindex = Value},
	      allow_opts = AllowOpts#ipcp_opts{maxslotindex = Value}
	     };
	_ ->
	    State
    end.

opt_addr(Key, Config) ->	    
    case proplists:get_value(Key, Config, <<0,0,0,0>>) of
	Addr when is_binary(Addr) ->
	    {Addr, Addr};
	Value = {Addr1, Addr2}
	  when is_binary(Addr1),
	       is_binary(Addr2) ->
	    Value
    end.

init(Link, Config) ->
    State0 = #state{link = Link, config = Config},
    State1 = init_opts(State0),

    FsmConfig = #fsm_config{
      passive = proplists:get_bool(passive, Config),
      silent = proplists:get_bool(silent, Config),
%%      restart = proplists:get_bool(restart, Config),
      term_restart_count = proplists:get_value(ipcp_max_terminate, Config, 2),
      conf_restart_count = proplists:get_value(ipcp_max_configure, Config, 10),
      failure_count = proplists:get_value(ipcp_max_failure, Config, 5),
      restart_timeout = proplists:get_value(ipcp_restart, Config, 3000)
     },

    {ok, ipcp, FsmConfig, State1}.

init_opts(State = #state{config = Config}) ->
    WantOpts = #ipcp_opts{
      neg_addr = not proplists:get_bool(ipcp_no_address, Config),
      accept_local = proplists:get_bool(accept_local, Config),
      accept_remote = proplists:get_bool(accept_remote, Config),
      usepeerdns = proplists:get_bool(usepeerdns, Config),
      neg_vj = opt_get_bool(vj, Config, true),
      vj_protocol = vjc,
      maxslotindex = ?MAX_STATES - 1,
      vjcflag = opt_get_bool(vjccomp, Config, true),

      ouraddr = proplists:get_value(ipcp_ouraddr, Config, <<0,0,0,0>>),
      hisaddr = proplists:get_value(ipcp_hisaddr, Config, <<0,0,0,0>>)
     },

    {Dns1, Dns2} = opt_addr(ms_dns, Config),
    {Wins1, Wins2}  = opt_addr(ms_wins, Config),
    AllowOpts = #ipcp_opts{
      neg_addr = not proplists:get_bool(ipcp_no_address, Config),
      neg_vj = opt_get_bool(vj, Config, true),
      vjcflag = opt_get_bool(vjccomp, Config, true),

      dnsaddr1 = Dns1,
      dnsaddr2 = Dns2,
      winsaddr1 = Wins1,
      winsaddr2 = Wins2
     },

    State0 = State#state{want_opts = WantOpts, allow_opts = AllowOpts},
    opt_vjslots(Config, State0).

%% fsm callback
resetci(State = #state{want_opts = WantOpts, allow_opts = AllowOpts}) ->
    WantOpts1 = WantOpts#ipcp_opts{
		  req_addr = (WantOpts#ipcp_opts.neg_addr and AllowOpts#ipcp_opts.neg_addr),
		  accept_local = (WantOpts#ipcp_opts.ouraddr == <<0,0,0,0>>),
		  accept_remote = (WantOpts#ipcp_opts.hisaddr == <<0,0,0,0>>),
		  req_dns1 = WantOpts#ipcp_opts.usepeerdns,
		  req_dns2 = WantOpts#ipcp_opts.usepeerdns
		 },
    State#state{want_opts = WantOpts1, got_opts = WantOpts1}.

addci(_StateName, State = #state{got_opts = GotOpts}) ->
    Options = ipcp_addcis(GotOpts),
    {Options, State}.

ackci(_StateName, Options, State = #state{got_opts = GotOpts}) ->
    Reply = ipcp_ackcis(Options, GotOpts),
    {Reply, State}.

nakci(StateName, Options, TreatAsReject,
      State = #state{got_opts = GotOpts}) ->
    DoUpdate = StateName /= opened,
    case ipcp_nakcis(Options, TreatAsReject, GotOpts, GotOpts, #ipcp_opts{}) of
	TryOpts when is_record(TryOpts, ipcp_opts) ->
	    if
		DoUpdate -> {true, State#state{got_opts = TryOpts}};
		true     -> {true, State}
	    end;
	Other -> {false, Other}
    end.

rejci(StateName, Options, State = #state{got_opts = GotOpts}) ->
    DoUpdate = StateName /= opened,
    case ipcp_rejcis(Options, GotOpts, GotOpts) of
	TryOpts when is_record(TryOpts, ipcp_opts) ->
	    if
		DoUpdate -> {true, State#state{got_opts = TryOpts}};
		true     -> {true, State}
	    end;
	Other -> {false, Other}
    end.

reqci(_StateName, Options, RejectIfDisagree,
      State = #state{want_opts = WantOpts, allow_opts = AllowedOpts}) ->
    {{Verdict, ReplyOpts}, WantOptsNew, HisOpts} =
	process_reqcis(Options, RejectIfDisagree, AllowedOpts, WantOpts),
    ReplyOpts1 = lists:reverse(ReplyOpts),
    NewState = State#state{want_opts = WantOptsNew, his_opts = HisOpts},
    {{Verdict, ReplyOpts1}, NewState}.

up(State) ->
    io:format("~p: Up~n", [?MODULE]),
    up_validate_neg_addr(State).

up_validate_neg_addr(State = #state{
		       want_opts = WantOpts,
		       got_opts = GotOpts,
		       his_opts = HisOpts0}) ->
    HisOpts1 = if not HisOpts0#ipcp_opts.neg_addr ->
		       HisOpts0#ipcp_opts{hisaddr = WantOpts#ipcp_opts.hisaddr};
		  true ->
		       HisOpts0
	       end,

    if (not GotOpts#ipcp_opts.neg_addr) andalso
       WantOpts#ipcp_opts.neg_addr andalso
       WantOpts#ipcp_opts.ouraddr /= <<0,0,0,0>> ->
        %% error("Peer refused to agree to our IP address");
	    Reply = {close, <<"Refused our IP address">>},
	    {Reply, State};

       GotOpts#ipcp_opts.ouraddr == <<0,0,0,0>> ->
	    Reply = {close, <<"Could not determine local IP address">>},
	    {Reply, State};

       HisOpts1#ipcp_opts.hisaddr == <<0,0,0,0>> ->
	    Reply = {close, <<"Could not determine remote IP address">>},
	    {Reply, State};

       true ->
	   up_validate_dns(State#state{his_opts = HisOpts1})
    end.

up_validate_dns(State = #state{
		  got_opts = GotOpts0,
		  his_opts = HisOpts}) ->

    GotOpts1 = if not GotOpts0#ipcp_opts.req_dns1 ->
		       GotOpts0#ipcp_opts{dnsaddr1 = <<0,0,0,0>>};
		  true ->
		       GotOpts0
	       end,
    GotOpts2 = if not GotOpts1#ipcp_opts.req_dns2 ->
		       GotOpts1#ipcp_opts{dnsaddr2 = <<0,0,0,0>>};
		  true ->
		       GotOpts1
	       end,
    NewState = State#state{got_opts = GotOpts2},

    %% TODO:
    %%  Apply Options

    Reply = {up, GotOpts2, HisOpts},
    {Reply, NewState}.

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
-define(IPCP_OPTS, [compresstype, addr, ms_dns1, ms_dns2]).

bool2int(true) -> 1;
bool2int(false) -> 0.
int2bool(1) -> true;
int2bool(0) -> false.

-spec ipcp_addci(AddOpt :: atom(),
		GotOpts :: #ipcp_opts{}) -> ppp_option().

ipcp_addci(compresstype, #ipcp_opts{
	     neg_vj = true, vj_protocol = Proto,  maxslotindex = MaxSlotId,
	     vjcflag = CompSlotId}) ->
    {compresstype, Proto, MaxSlotId, bool2int(CompSlotId)};

ipcp_addci(addr, #ipcp_opts{neg_addr = true, ouraddr = OurAddr}) ->
    {addr, OurAddr};

ipcp_addci(ms_dns1, #ipcp_opts{req_dns1 = true, dnsaddr1 = DnsAddr}) ->
    {ms_dns1, DnsAddr};

ipcp_addci(ms_dns2, #ipcp_opts{req_dns2 = true, dnsaddr2 = DnsAddr}) ->
    {ms_dns2, DnsAddr};
 
ipcp_addci(_, _) ->
    [].

ipcp_addcis(GotOpts) ->
    [ipcp_addci(Opt, GotOpts) || Opt <- ?IPCP_OPTS].

%%===================================================================
%% Option Validations
-spec ipcp_nakci(NakOpt :: ppp_option(),
		 TreatAsReject :: boolean(),
		 GotOpts :: #ipcp_opts{},
		 TryOpts :: #ipcp_opts{},
		 NakOpts :: #ipcp_opts{}) -> {#ipcp_opts{}, #ipcp_opts{}}.


ipcp_nakci({compresstype, _, _, _}, true, #ipcp_opts{neg_vj = true}, TryOpts, NakOpts) ->
    T1 = TryOpts#ipcp_opts{neg_vj = false},
    N1 = NakOpts#ipcp_opts{neg_vj = true},
    {T1, N1};

ipcp_nakci({compresstype, vjc, NakMaxSlotId, NakCompSlotId}, _,
	   GotOpts = #ipcp_opts{neg_vj = true}, TryOpts, NakOpts) ->
    T1 = if NakMaxSlotId < GotOpts#ipcp_opts.maxslotindex ->
		 TryOpts#ipcp_opts{maxslotindex = NakMaxSlotId};
	    true -> TryOpts#ipcp_opts{neg_vj = false}
	 end,
    T2 = if (NakCompSlotId == 0) ->
		 T1#ipcp_opts{vjcflag = false};
	    true -> T1
	 end,
    N1 = NakOpts#ipcp_opts{neg_vj = true},
    {T2, N1};

ipcp_nakci({compresstype, _, _, _}, _,
	   #ipcp_opts{neg_vj = false}, TryOpts,
	   NakOpts = #ipcp_opts{neg_vj = false}) ->
    N1 = NakOpts#ipcp_opts{neg_vj = true},
    {TryOpts, N1};

ipcp_nakci({addr, _}, true, #ipcp_opts{neg_addr = true},TryOpts, NakOpts) ->
    T1 = TryOpts#ipcp_opts{neg_addr = false},
    N1 = NakOpts#ipcp_opts{neg_addr = true},
    {T1, N1};

ipcp_nakci({addr, NakOurAddr}, _, GotOpts = #ipcp_opts{neg_addr = true},
	   TryOpts, NakOpts) ->
    T1 = if (GotOpts#ipcp_opts.accept_local) and (NakOurAddr /= <<0,0,0,0>>) ->
		 TryOpts#ipcp_opts{ouraddr = NakOurAddr};
	    true -> TryOpts
	 end,
    N1 = NakOpts#ipcp_opts{neg_addr = true},
    {T1, N1};

ipcp_nakci({addr, NakOurAddr}, _, GotOpts = #ipcp_opts{neg_addr = false},
	   TryOpts, NakOpts = #ipcp_opts{neg_addr = false}) ->
    T1 = if GotOpts#ipcp_opts.accept_local ->
		 TryOpts#ipcp_opts{ouraddr = NakOurAddr};
	    true -> TryOpts
	 end,
    T2 = T1#ipcp_opts{neg_addr = (T1#ipcp_opts.ouraddr /= <<0,0,0,0>>)},
    N1 = NakOpts#ipcp_opts{neg_addr = true},
    {T2, N1};

ipcp_nakci({ms_dns1, _}, true, #ipcp_opts{req_dns1 = true}, TryOpts, NakOpts) ->
    T1 = TryOpts#ipcp_opts{req_dns1 = false},
    N1 = NakOpts#ipcp_opts{req_dns1 = true},
    {T1, N1};

ipcp_nakci({ms_dns1, NakDnsAddr}, _, #ipcp_opts{req_dns1 = true},
	   TryOpts, NakOpts) ->
    T1 = TryOpts#ipcp_opts{dnsaddr1 = NakDnsAddr},
    N1 = NakOpts#ipcp_opts{req_dns1 = true},
    {T1, N1};

ipcp_nakci({ms_dns1, NakDnsAddr}, _, #ipcp_opts{req_dns1 = false},
	   TryOpts, NakOpts = #ipcp_opts{req_dns1 = false}) ->
    T1 = TryOpts#ipcp_opts{req_dns1 = true, dnsaddr1 = NakDnsAddr},
    N1 = NakOpts#ipcp_opts{req_dns1 = true},
    {T1, N1};

ipcp_nakci({ms_dns2, _}, true, #ipcp_opts{req_dns2 = true}, TryOpts, NakOpts) ->
    T1 = TryOpts#ipcp_opts{req_dns2 = false},
    N1 = NakOpts#ipcp_opts{req_dns2 = true},
    {T1, N1};

ipcp_nakci({ms_dns2, NakDnsAddr}, _, #ipcp_opts{req_dns2 = true},
	   TryOpts, NakOpts) ->
    T1 = TryOpts#ipcp_opts{dnsaddr2 = NakDnsAddr},
    N1 = NakOpts#ipcp_opts{req_dns2 = true},
    {T1, N1};

ipcp_nakci({ms_dns2, NakDnsAddr}, _, #ipcp_opts{req_dns2 = false},
	   TryOpts, NakOpts = #ipcp_opts{req_dns2 = false}) ->
    T1 = TryOpts#ipcp_opts{req_dns2 = true, dnsaddr2 = NakDnsAddr},
    N1 = NakOpts#ipcp_opts{req_dns2 = true},
    {T1, N1};

ipcp_nakci(_, _, _, _, _) ->
    false.

%%TODO: does this really matter?
%%
%% RFC1661 says:
%%   Options from the Configure-Request MUST NOT be reordered
%% we do not enforce ordering here, pppd does
%%
%% Note: on generating Ack/Naks we do preserve ordering!
%%
ipcp_nakcis([], _TreatAsReject, _, TryOpts, _) ->
    io:format("ipcp_nakcis: ~p~n", [TryOpts]),
    TryOpts;
ipcp_nakcis([Opt|Options], TreatAsReject, GotOpts, TryOpts, NakOpts) ->
    case ipcp_nakci(Opt, TreatAsReject, GotOpts, TryOpts, NakOpts) of
	{NewTryOpts, NewNakOpts} ->
	    ipcp_nakcis(Options, TreatAsReject, GotOpts, NewTryOpts, NewNakOpts);
	_ ->
	    io:format("ipcp_nakcis: received bad Nakt!~n"),
	    false
    end.

-spec ipcp_rejci(RejOpt :: ppp_option(),
		 GotOpts :: #ipcp_opts{},
		 TryOpts :: #ipcp_opts{}) -> #ipcp_opts{}.

ipcp_rejci({compresstype, Proto, MaxSlotId, RejCompSlotId},
	  #ipcp_opts{
	     neg_vj = true, vj_protocol = Proto,  maxslotindex = MaxSlotId,
	     vjcflag = CompSlotId
	    }, TryOpts) ->
    case int2bool(RejCompSlotId) of
	CompSlotId ->
	    TryOpts#ipcp_opts{neg_vj = false};
	_ ->
	    false
    end;

ipcp_rejci({addr, OurAddr}, #ipcp_opts{ouraddr = OurAddr}, TryOpts) ->
    TryOpts#ipcp_opts{neg_addr = false};

ipcp_rejci({ms_dns1, DnsAddr}, #ipcp_opts{dnsaddr1 = DnsAddr}, TryOpts) ->
    TryOpts#ipcp_opts{req_dns1 = false};

ipcp_rejci({ms_dns2, DnsAddr}, #ipcp_opts{dnsaddr2 = DnsAddr}, TryOpts) ->
    TryOpts#ipcp_opts{req_dns2 = false};

ipcp_rejci(_, _, _) ->
    false.

%%TODO: does this really matter?
%%
%% RFC1661 says:
%%   Options from the Configure-Request MUST NOT be reordered
%% we do not enforce ordering here, pppd does
%%
%% Note: on generating Ack/Naks we do preserve ordering!
%%
ipcp_rejcis([], _, TryOpts) ->
    TryOpts;
ipcp_rejcis([RejOpt|RejOpts], GotOpts, TryOpts) ->
    case ipcp_rejci(RejOpt, GotOpts, TryOpts) of
	NewTryOpts when is_record(NewTryOpts, ipcp_opts) ->
	    ipcp_rejcis(RejOpts, GotOpts, NewTryOpts);
	_ ->
	    io:format("ipcp_rejcis: received bad Reject!~n"),
	    false
    end.

-spec ipcp_ackci(AckOpt :: ppp_option(),
		 GotOpts :: #ipcp_opts{}) -> true | false.

ipcp_ackci({compresstype, AckProto, AckMaxSlotId, AckCompSlotId},
	   #ipcp_opts{
	     neg_vj = GotIt, vj_protocol = GotProto,  maxslotindex = GotMaxSlotId,
	     vjcflag = GotCompSlotId}) ->
    GotIt
	and (AckProto == GotProto)
	and (AckMaxSlotId == GotMaxSlotId)
	and (int2bool(AckCompSlotId) == GotCompSlotId);

ipcp_ackci({addr, AckOurAddr}, #ipcp_opts{neg_addr = GotIt, ouraddr = GotOurAddr}) ->
    GotIt and (AckOurAddr == GotOurAddr);

ipcp_ackci({ms_dns1, AckDnsAddr}, #ipcp_opts{req_dns1 = GotIt, dnsaddr1 = GotDnsAddr}) ->
    GotIt and (AckDnsAddr == GotDnsAddr);

ipcp_ackci({ms_dns2, AckDnsAddr}, #ipcp_opts{req_dns2 = GotIt, dnsaddr2 = GotDnsAddr}) ->
    GotIt and (AckDnsAddr == GotDnsAddr);

ipcp_ackci(Ack, _) ->
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
ipcp_ackcis([], _) ->
    true;
ipcp_ackcis([AckOpt|AckOpts], GotOpts) ->
    case ipcp_ackci(AckOpt, GotOpts) of
	false ->
	    io:format("ipcp_ackcis: received bad Ack! ~p, ~p~n", [AckOpt, GotOpts]),
	    false;
	_ ->
	    ipcp_ackcis(AckOpts, GotOpts)
    end.

-spec ipcp_reqci(ReqOpt :: ppp_option(),
		 AllowedOpts :: #ipcp_opts{},
		 WantOpts :: #ipcp_opts{},
		 HisOpts :: #ipcp_opts{}) ->
			{Verdict :: atom() | {atom() | ppp_option()},
			 WantOptsNew :: #ipcp_opts{},
			 HisOptsNew :: #ipcp_opts{}}.

ipcp_reqci({compresstype, ReqProto, _, _},
	   #ipcp_opts{neg_vj = true}, WantOpts, HisOpts)
  when ReqProto /=  ?IPCP_VJC_COMP->
    {rej, WantOpts, HisOpts};
ipcp_reqci({compresstype, ReqProto, ReqMaxSlotId, ReqCompSlotId},
	    #ipcp_opts{
	     neg_vj = true, vj_protocol = AllowedProto, maxslotindex = AllowedMaxSlotId,
	     vjcflag = AllowedCompSlotId
	    }, WantOpts, HisOpts) ->
    ReqVjcFlag = int2bool(ReqCompSlotId),
    if ReqMaxSlotId > AllowedMaxSlotId ->
	    Verdict = {nack, {compresstype, AllowedProto, AllowedMaxSlotId, bool2int(AllowedCompSlotId)}};
       ReqVjcFlag and not AllowedCompSlotId ->
	    Verdict = {nack, {compresstype, AllowedProto, ReqMaxSlotId, bool2int(WantOpts#ipcp_opts.vjcflag)}};
       true ->
	    Verdict = ack
    end,
    HisOptsNew = HisOpts#ipcp_opts{neg_vj = true, vj_protocol = ReqProto,
				   maxslotindex = ReqMaxSlotId, vjcflag = int2bool(ReqCompSlotId)},
    {Verdict, WantOpts, HisOptsNew};
    
%% If he has no address, or if we both have his address but
%% disagree about it, then NAK it with our idea.
%% In particular, if we don't know his address, but he does,
%% then accept it.
ipcp_reqci({addr, ReqHisAddr}, #ipcp_opts{neg_addr = true}, WantOpts, HisOpts) ->
    if 
	(ReqHisAddr /= WantOpts#ipcp_opts.hisaddr) and
	((ReqHisAddr == <<0,0,0,0>>) or not (WantOpts#ipcp_opts.accept_remote)) ->
	    Verdict = {nack, {addr, WantOpts#ipcp_opts.hisaddr}},
	    HisOptsNew = HisOpts#ipcp_opts{neg_addr = true, hisaddr = ReqHisAddr},
	    WantOptsNew = WantOpts;
	(ReqHisAddr == <<0,0,0,0>>) and (WantOpts#ipcp_opts.hisaddr == <<0,0,0,0>>) ->
	    Verdict = rej,
	    HisOptsNew = HisOpts,
	    WantOptsNew = WantOpts#ipcp_opts{req_addr = false};
	true ->
	    Verdict = ack,
	    HisOptsNew = HisOpts#ipcp_opts{neg_addr = true, hisaddr = ReqHisAddr},
	    WantOptsNew = WantOpts
    end,
    {Verdict, WantOptsNew, HisOptsNew};

ipcp_reqci({ms_dns1, ReqDnsAddr}, #ipcp_opts{dnsaddr1 = AllowedDnsAddr}, WantOpts, HisOpts)
  when AllowedDnsAddr /= <<0,0,0,0>> ->
    if ReqDnsAddr /= AllowedDnsAddr ->
	    Verdict = {nack, {ms_dns1, AllowedDnsAddr}};
       true ->
	    Verdict = ack
    end,
    {Verdict, WantOpts, HisOpts};

ipcp_reqci({ms_dns2, ReqDnsAddr}, #ipcp_opts{dnsaddr2 = AllowedDnsAddr}, WantOpts, HisOpts)
  when AllowedDnsAddr /= <<0,0,0,0>> ->
    if ReqDnsAddr /= AllowedDnsAddr ->
	    Verdict = {nack, {ms_dns2, AllowedDnsAddr}};
       true ->
	    Verdict = ack
    end,
    {Verdict, WantOpts, HisOpts};

ipcp_reqci({ms_wins1, ReqWinsAddr}, #ipcp_opts{winsaddr1 = AllowedWinsAddr}, WantOpts, HisOpts)
  when AllowedWinsAddr /= <<0,0,0,0>> ->
    if ReqWinsAddr /= AllowedWinsAddr ->
	    Verdict = {nack, {ms_wins1, AllowedWinsAddr}};
       true ->
	    Verdict = ack
    end,
    {Verdict, WantOpts, HisOpts};

ipcp_reqci({ms_wins2, ReqWinsAddr}, #ipcp_opts{winsaddr2 = AllowedWinsAddr}, WantOpts, HisOpts)
  when AllowedWinsAddr /= <<0,0,0,0>> ->
    if ReqWinsAddr /= AllowedWinsAddr ->
	    Verdict = {nack, {ms_wins2, AllowedWinsAddr}};
       true ->
	    Verdict = ack
    end,
    {Verdict, WantOpts, HisOpts};

ipcp_reqci(Req, _, WantOpts, HisOpts) ->
    io:format("lcp_reqci: rejecting: ~p~n", [Req]),
    io:format("His: ~p~n", [HisOpts]),
    {rej, WantOpts, HisOpts}.

process_reqcis(Options, RejectIfDisagree, AllowedOpts, WantOpts) ->
    process_reqcis(Options, RejectIfDisagree, AllowedOpts, WantOpts, #ipcp_opts{}, [], [], []).

process_reqcis([], _RejectIfDisagree, _AllowedOpts, WantOpts, HisOpts, _AckReply, _NackReply, RejReply)
  when length(RejReply) /= 0 ->
    Reply = {rej, RejReply},
    {Reply, WantOpts, HisOpts};

%% If we aren't rejecting this packet, and we want to negotiate
%% their address, and they didn't send their address, then we
%% send a NAK with a CI_ADDR option appended.
process_reqcis([], _RejectIfDisagree, _AllowedOpts, WantOpts, HisOpts, _AckReply, NackReply, _RejReply)
  when not HisOpts#ipcp_opts.neg_addr and WantOpts#ipcp_opts.req_addr ->
    if length(NackReply) /= 0 ->
	    NewWantOpts = WantOpts;
       true ->
	    NewWantOpts = WantOpts#ipcp_opts{req_addr = false}     %% don't ask again
    end,
    Reply = {nack, [{addr, WantOpts#ipcp_opts.hisaddr}|NackReply]},
    {Reply, NewWantOpts, HisOpts};
    
process_reqcis([], _RejectIfDisagree, _AllowedOpts, WantOpts, HisOpts, AckReply, NackReply, _RejReply) ->
    Reply = if
		length(NackReply) /= 0 -> {nack, NackReply};
		true -> {ack, AckReply}
	    end,
    {Reply, WantOpts, HisOpts};
   

process_reqcis([Opt|Options], RejectIfDisagree, AllowedOpts, WantOpts, HisOpts, AckReply, NAckReply, RejReply) ->
    {Verdict, WantOptsNew, HisOptsNew} = ipcp_reqci(Opt, AllowedOpts, WantOpts, HisOpts),
    case Verdict of
	ack ->
	    process_reqcis(Options, RejectIfDisagree, AllowedOpts, WantOptsNew, HisOptsNew, [Opt|AckReply], NAckReply, RejReply);
	{nack, _} when RejectIfDisagree ->
	    process_reqcis(Options, RejectIfDisagree, AllowedOpts, WantOptsNew, HisOptsNew, AckReply, NAckReply, [Opt|RejReply]);
	{nack, NewOpt} ->
	    process_reqcis(Options, RejectIfDisagree, AllowedOpts, WantOptsNew, HisOptsNew, AckReply, [NewOpt|NAckReply], RejReply);
	rej ->
	    process_reqcis(Options, RejectIfDisagree, AllowedOpts, WantOptsNew, HisOptsNew, AckReply, NAckReply, [Opt|RejReply])
    end.
