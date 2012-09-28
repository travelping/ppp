-module(ppp_pap).

-behaviour(ppp_proto).
-behaviour(gen_server).

%% API
-export([start_link/2]).
-export([frame_in/2, lowerup/1, lowerdown/1, loweropen/1, lowerclose/2, protrej/1]).
-export([auth_peer/1, auth_withpeer/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

%% FSM callbacks
-export([c_initial/2, c_closed/2, c_pending/2, c_authreq/2, c_open/2,c_badauth/2]).
-export([s_initial/2, s_closed/2, s_pending/2, s_listen/2, s_open/2, s_badauth/2]).

-define(SERVER, ?MODULE). 

-include_lib("eradius/include/eradius_lib.hrl").
-include_lib("eradius/include/eradius_dict.hrl").
-include_lib("eradius/include/dictionary.hrl").

%% Client states.
-type client_state() ::
	c_initial			%% Connection down
      | c_closed			%% Connection up haven't requested auth
      | c_pending			%% Connection down have requested auth
      | c_authreq			%% We've sent an Authenticate-Request
      | c_open				%% We've received an Ack
      | c_badauth.			%% We've received a Nak

%% Server states.
-type server_state() ::
	s_initial			%% Connection down
      | s_closed			%% Connection up haven't requested auth
      | s_pending			%% Connection down have requested auth
      | s_listen			%% Listening for an Authenticate
      | s_open				%% We've sent an Ack
      | s_badauth.			%% We've sent a Nak

-define(DEFTIMEOUT, 3000).		%% Timeout for retransmitting req
-define(DEFREQTIME, 30000).		%% Time to wait for auth-req from peer

-record(state, {
	  link			:: pid(),
	  
	  c_state = c_initial	:: client_state(),
	  c_timer		:: undefined | reference(),
	  s_state = s_initial	:: server_state(),
	  s_timer		:: undefined | reference(),

	  username = <<>>	:: binary(),
	  passwd = <<>>		:: binary(),

	  reqid = 0		:: integer(),

	  timeouttime = 0	:: integer(),		%% Timeout for auth-req retrans
	  transmits = 0		:: integer(),		%% Number of auth-reqs sent
	  maxtransmits = 0	:: integer(),		%% Maximum number of auth-reqs to send
	  reqtimeout = 0	:: integer()		%% Time to wait for auth-req from peer
	 }).

%%%===================================================================
%%% Protocol API
%%%===================================================================

start_link(Link, Config) ->
    gen_server:start_link(?MODULE, [Link, Config], []).

lowerup(FSM) ->
    gen_server:call(FSM, lowerup).

lowerdown(FSM) ->
    gen_server:call(FSM, lowerdown).

loweropen(_FSM) ->
    ok.

lowerclose(_FSM, _Reason) ->
    ok.

protrej(FSM) ->
    gen_server:call(FSM, protrej).

frame_in(FSM, Frame) ->
    gen_server:call(FSM, Frame).

%%%===================================================================
%%% API
%%%===================================================================

%% Authenticate our peer (start server).
auth_peer(FSM) ->
    gen_server:call(FSM, auth_peer).

%% Authenticate us with our peer (start client).
auth_withpeer(FSM, UserName, Password) ->
    gen_server:call(FSM, {auth_withpeer, UserName, Password}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Link, Config]) ->
    State = #state{
      link = Link,
      timeouttime = proplists:get_value('pap-restart', Config, ?DEFTIMEOUT),
      maxtransmits = proplists:get_value('pap-max-authreq', Config, 10),
      reqtimeout = proplists:get_value('pap-timeout', Config, ?DEFREQTIME)
     },

    {ok, State}.

handle_call(Event, _From, State)
  when Event == lowerup; Event == lowerdown ->
    {_, NewState0} = fsm_client_cast(Event, State),
    {_, NewState1} = fsm_server_cast(Event, NewState0),
    {reply, ok, NewState1};

handle_call(Frame = {pap, 'PAP-Authentication-Request', _, _, _}, _From, State) ->
    io:format("~p(~p): got ~p~n", [?MODULE, ?LINE, Frame]),
    fsm_server_call(Frame, State);

handle_call(Frame = {pap, Code, _, _}, _From, State)
  when Code == 'PAP-Authenticate-Ack';
       Code == 'PAP-Authenticate-Nak'->
    io:format("~p(~p): got ~p~n", [?MODULE, ?LINE, Frame]),
    fsm_client_call(Frame, State);

handle_call(auth_peer, _From, State) ->
    fsm_server_call(auth_peer, State);

handle_call({auth_withpeer, UserName, Password}, _From, State) ->
    NewState = State#state{username = UserName, passwd = Password},
    fsm_client_call(auth_withpeer, NewState);

handle_call(protrej, _From, State) ->
    {_, NewState0} = fsm_client_call(protrej, State),
    {_, NewState1} = fsm_server_call(protrej, NewState0),

    %% protrej always results in lowerdown...
    {_, NewState2} = fsm_client_call(lowerdown, NewState1),
    {_, NewState3} = fsm_server_call(lowerdown, NewState2),

    {reply, ok, NewState3};

handle_call(Event, _From, State) ->
    io:format("~p(~p): got ~p~n", [?MODULE, ?LINE, Event]),
    {_, NewState0} = fsm_client_call(Event, State),
    {_, NewState1} = fsm_server_call(Event, NewState0),
    {reply, ok, NewState1}.

handle_cast(_Event, State) ->
    {noreply, State}.

handle_info({timeout, TimerRef, timeout}, State = #state{c_timer = TimerRef}) ->
    %% client timer expired
    NewState = State#state{c_timer = undefined},
    fsm_client_cast(timeout, NewState);

handle_info({timeout, TimerRef, timeout}, State = #state{s_timer = TimerRef}) ->
    %% client timer expired
    NewState = State#state{s_timer = undefined},
    fsm_server_cast(timeout, NewState);

handle_info(_Info, State) ->
    {noreply, State}.
	
terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% PAP Client FSM
%%%===================================================================
%%
%% Connection down
%%
c_initial(lowerup, State) ->
    {reply, ok, c_closed, State};
c_initial(lowerdown, State) ->
    {reply, ok, c_initial, State};
c_initial(auth_withpeer, State) ->
    {reply, ok, c_pending, State};
c_initial(_Msg, State) ->
    {reply, ok, c_initial, State}.

%%
%% Connection up haven't requested auth
%%
c_closed(lowerdown, State) ->
    {reply, ok, c_initial, State};
c_closed(auth_withpeer, State) ->
    NewState = send_authentication_request(State),
    {reply, ok, c_authreq, NewState};
c_closed(_Msg, State) ->
    {reply, ok, c_closed, State}.

%%
%% Connection down have requested auth
%%
c_pending(lowerup, State) ->
    NewState = send_authentication_request(State),
    {reply, ok, c_authreq, NewState};
c_pending(lowerdown, State) ->
    {reply, ok, c_initial, State};
c_pending(auth_withpeer, State) ->
    {reply, ok, c_pending, State};
c_pending(_Msg, State) ->
    {reply, ok, c_pending, State}.

%%
%% We've sent an Authenticate-Request
%%
c_authreq(lowerdown, State) ->
    NewState = stop_c_timer(State),
    {reply, ok, c_initial, NewState};

c_authreq(protrej, State) ->
    %% error("PAP authentication failed due to protocol-reject");
    {reply, {auth_withpeer, fail}, c_authreq, State};

c_authreq(timeout, State = #state{
		     link = Link,
		     transmits = Transmits,
		     maxtransmits = MaxTransmits})
  when Transmits >= MaxTransmits ->
    %% error("No response to PAP authenticate-requests");
    ppp_link:auth_withpeer(Link, pap, fail),
    {reply, ok, c_badauth, State};

c_authreq(timeout, State) ->
    NewState = send_authentication_request(State),
    {reply, ok, c_authreq, NewState};

c_authreq({pap, 'PAP-Authenticate-Ack', _Id, Msg}, State) ->
    io:format("PAP: ~p~n", [Msg]),
    {reply, {auth_withpeer, success}, c_open, State};

c_authreq({pap, 'PAP-Authenticate-Nak', _Id, Msg}, State) ->
    %% error("PAP authentication failed");
    io:format("PAP: ~p~n", [Msg]),
    {reply, {auth_withpeer, fail}, c_badauth, State};

c_authreq(_Msg, State) ->
    {reply, ok, c_authreq, State}.

%%
%% We've received an Ack
%%
c_open(lowerdown, State) ->
    {reply, ok, c_initial, State};
c_open(_Msg, State) ->
    {reply, ok, c_open, State}.

%%
%% We've received a Nak
%%
c_badauth(lowerdown, State) ->
    {reply, ok, c_initial, State};
c_badauth(_Msg, State) ->
    {reply, ok, c_badauth, State}.

%%%===================================================================
%%% PAP Server FSM
%%%===================================================================

%% Connection down
s_initial(lowerup, State) ->
    {reply, ok, s_closed, State};
s_initial(lowerdown, State) ->
    {reply, ok, s_initial, State};
s_initial(auth_peer, State) ->
    {reply, ok, s_pending, State};
s_initial(_Msg, State) ->
    {reply, ok, s_initial, State}.

%% Connection up haven't requested auth
s_closed(lowerdown, State) ->
    {reply, ok, s_initial, State};
s_closed(auth_peer, State) ->
    NewState = rearm_s_timer(State),
    {reply, ok, s_listen, NewState};
s_closed(_Msg, State) ->
    {reply, ok, s_closed, State}.

%% Connection down have requested auth
s_pending(lowerup, State) ->
    NewState = rearm_s_timer(State),
    {reply, ok, s_listen, NewState};
s_pending(lowerdown, State) ->
    {reply, ok, s_initial, State};
s_pending(auth_peer, State) ->
    {reply, ok, s_pending, State};
s_pending(_Msg, State) ->
    {reply, ok, s_pending, State}.

%% Listening for an Authenticate
s_listen(lowerdown, State) ->
    NewState = stop_s_timer(State),
    {reply, ok, s_initial, NewState};
s_listen(protrej, State) ->
    %% error("PAP authentication of peer failed (protocol-reject)");
    {reply, {auth_peer, fail}, s_listen, State};
s_listen(timeout, State = #state{link = Link}) ->
    ppp_link:auth_peer(Link, pap, fail),
    {reply, ok, s_badauth, State};

s_listen({pap, 'PAP-Authentication-Request', Id, PeerId, Passwd}, State) ->
    NewState0 = stop_s_timer(State),
    case check_passwd(PeerId, Passwd) of
	{success, Opts} ->
	    %% notice("PAP peer authentication succeeded for %q", rhostname);
	    NewState1 = send_authentication_ack(Id, <<"">>, NewState0),
	    {reply, {auth_peer, success, PeerId, Opts}, s_open, NewState1};
	_ ->
	    %% warn("PAP peer authentication failed for %q", rhostname);
	    NewState1 = send_authentication_nak(Id, <<"">>, NewState0),
	    {reply, {auth_peer, fail}, s_badauth, NewState1}
    end;

s_listen(_Msg, State) ->
    {reply, ok, s_listen, State}.

%% We've sent an Ack
s_open(lowerdown, State) ->
    {reply, ok, s_initial, State};
s_open({pap, 'PAP-Authentication-Request', Id, _, _}, State) ->
    NewState = send_authentication_ack(Id, <<"">>, State),
    {reply, ok, s_open, NewState};
s_open(_Msg, State) ->
    {reply, ok, s_open, State}.

%% We've sent a Nak
s_badauth(lowerdown, State) ->
    {reply, ok, s_initial, State};
s_badauth({pap, 'PAP-Authentication-Request', Id, _, _}, State) ->
    NewState = send_authentication_nak(Id, <<"">>, State),
    {reply, ok, s_badauth, NewState};
s_badauth(_Msg, State) ->
    {reply, ok, s_badauth, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

fsm_cast_reply(Element, {reply, _Reply, NextStateName, NewStateData}) ->
    {noreply, setelement(Element, NewStateData, NextStateName)};

%% TODO: do we allow stop?
fsm_cast_reply(_Element, {stop, Reason, NewStateData}) ->
    {stop, Reason, NewStateData}.
			 
fsm_server_cast(Msg, State = #state{s_state = StateName}) ->
    fsm_cast_reply(#state.s_state, ?MODULE:StateName(Msg, State)).

fsm_client_cast(Msg, State = #state{c_state = StateName}) ->
    fsm_cast_reply(#state.c_state, ?MODULE:StateName(Msg, State)).

fsm_call_reply(Element, {reply, Reply, NextStateName, NewStateData}) ->
    io:format("new state ~p~n", [NextStateName]),
    {reply, Reply, setelement(Element, NewStateData, NextStateName)};

%% TODO: do we allow stop?
fsm_call_reply(_Element, {stop, Reason, NewStateData}) ->
    {stop, Reason, NewStateData}.
			 
fsm_server_call(Msg, State = #state{s_state = StateName}) ->
    io:format("server_call in ~p~n", [StateName]),
    fsm_call_reply(#state.s_state, ?MODULE:StateName(Msg, State)).

fsm_client_call(Msg, State = #state{c_state = StateName}) ->
    io:format("client_call in ~p~n", [StateName]),
    fsm_call_reply(#state.c_state, ?MODULE:StateName(Msg, State)).

%%===================================================================

rearm_c_timer(State = #state{c_timer = TimerRef, timeouttime = Timeout}) ->
    if is_reference(TimerRef) -> erlang:cancel_timer(TimerRef);
       true -> ok
    end,
    
    State#state{c_timer = erlang:start_timer(Timeout, self(), timeout)}.
 
stop_c_timer(State = #state{c_timer = TimerRef}) ->
    if is_reference(TimerRef) -> erlang:cancel_timer(TimerRef);
       true -> ok
    end,
    State#state{c_timer = undefined}.

rearm_s_timer(State = #state{s_timer = TimerRef, reqtimeout = Timeout}) ->
    if is_reference(TimerRef) -> erlang:cancel_timer(TimerRef);
       true -> ok
    end,
    
    State#state{s_timer = erlang:start_timer(Timeout, self(), timeout)}.
 
stop_s_timer(State = #state{s_timer = TimerRef}) ->
    if is_reference(TimerRef) -> erlang:cancel_timer(TimerRef);
       true -> ok
    end,
    State#state{s_timer = undefined}.

link_send(Link, Data) ->
    ppp_link:send(Link, Data).

send_packet(Packet, State = #state{link = Link}) ->
    io:format("PAP Sending: ~p~n", [Packet]),
    Data = ppp_frame:encode(Packet),
    link_send(Link, Data),
    State.

send_authentication_request(State = #state{
			      reqid = Id,
			      transmits = Transmits,
			      username = UserName,
			      passwd = Password
			     }) ->
    NewId = Id + 1,
    NewState1 = rearm_c_timer(State),
    NewState2 = NewState1#state{reqid = NewId, transmits = Transmits + 1},
    send_packet({pap, 'PAP-Authentication-Request', NewId, UserName, Password}, NewState2).

send_authentication_ack(Id, Msg, State) ->
    send_packet({pap, 'PAP-Authenticate-Ack', Id, Msg}, State).

send_authentication_nak(Id, Msg, State) ->
    send_packet({pap, 'PAP-Authenticate-Nak', Id, Msg}, State).

%%===================================================================
%% Password Logic
%%
%% check_passwd(<<"test">>, <<"secret">>) ->
%%     success;
%% check_passwd(PeerId, PeerId) ->
%%     success;
%% check_passwd(_PeerId, _Passwd) ->
%%     fail.

check_passwd(PeerId, Passwd) ->
    Attrs = [
	     {?User_Name, PeerId},
	     {?User_Password , Passwd},
	     {?Service_Type, 2},
	     {?Framed_Protocol, 1}
	    ],
    Req = #radius_request{
	     cmd = request,
	     attrs = Attrs,
	     msg_hmac = true},
    {ok, NAS} = application:get_env(radius_auth_server),
    radius_response(eradius_client:send_request(NAS, Req), NAS).

radius_response({ok, Response}, {_, _, Secret}) ->
    radius_reply(eradius_lib:decode_request(Response, Secret));
radius_response(Response, _) ->
    io:format("RADIUS failed with ~p~n", [Response]),
    fail.

radius_reply(#radius_request{cmd = accept} = Reply) ->
    io:format("RADIUS Reply: ~p~n", [Reply]),
    case process_radius_attrs(fun process_pap_attrs/2, success, Reply) of
	{success, _} = Result ->
	    Result;
	_ ->
	    fail
    end;
radius_reply(#radius_request{cmd = reject} = Reply) ->
    io:format("RADIUS failed with ~p~n", [Reply]),
    fail;
radius_reply(Reply) ->
    io:format("RADIUS failed with ~p~n", [Reply]),
    fail.

%% iterate over the RADIUS attributes
process_radius_attrs(Fun, Verdict, #radius_request{attrs = Attrs}) ->
    lists:foldr(Fun, {Verdict, []}, Attrs).

process_pap_attrs(AVP, {_Verdict, _Opts} = Acc0) ->
    process_gen_attrs(AVP, Acc0).

%% Service-Type = Framed-User
process_gen_attrs({#attribute{id = ?Service_Type}, 2}, {_Verdict, _Opts} = Acc0) ->
    Acc0;
process_gen_attrs(AVP = {#attribute{id = ?Service_Type}, _}, Acc0) ->
    process_unexpected_value(AVP, Acc0);

%% Framed-Protocol = PPP
process_gen_attrs({#attribute{id = ?Framed_Protocol}, 1}, {_Verdict, _Opts} = Acc0) ->
    Acc0;
process_gen_attrs(AVP = {#attribute{id = ?Framed_Protocol}, _}, Acc0) ->
    process_unexpected_value(AVP, Acc0);

%% Framed-IP-Address = xx.xx.xx.xx
process_gen_attrs({#attribute{id = ?Framed_IP_Address}, {255,255,255,255}}, {Verdict, Opts} = _Acc0) ->
    %% user should be allowed to select one
    {Verdict, [{ipcp_hisaddr, <<0,0,0,0>>}, {accept_remote, true}|Opts]};
process_gen_attrs({#attribute{id = ?Framed_IP_Address}, {255,255,255,254}}, {Verdict, Opts} = _Acc0) ->
    %% NAS should select an ip address
    {Verdict, [{choose_ip, true}, {accept_remote, false}|Opts]};
process_gen_attrs({#attribute{id = ?Framed_IP_Address}, {A, B, C, D}}, {Verdict, Opts} = _Acc0) ->
    {Verdict, [{ipcp_hisaddr, <<A, B, C, D>>}, {accept_remote, false}|Opts]};

process_gen_attrs({#attribute{name = Name}, Value} , {_Verdict, _Opts} = Acc0) ->
    io:format("unhandled reply AVP: ~s: ~p~n", [Name, Value]),
    Acc0.

process_unexpected_value({#attribute{name = Name}, Value} , {_Verdict, Opts} = _Acc0) ->
    io:format("unexpected Value in AVP: ~s: ~p~n", [Name, Value]),
    {fail, Opts}.
