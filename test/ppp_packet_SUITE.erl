%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

%%%-------------------------------------------------------------------
%%% @author Andreas Schultz <aschultz@tpip.net>
%%% @copyright (C) 2011, Andreas Schultz
%%% @doc
%%%
%%% @end
%%% Created : 29 Jun 2011 by Andreas Schultz <aschultz@tpip.net>
%%%-------------------------------------------------------------------
-module(ppp_packet_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").

pppoe_padt() ->
    hexstr2bin("11a700000031010300041004e1d80101"
	       "000573706172630105001c00000de901"
	       "164369726375697449442061746d2030"
	       "2f323a312e3332").

pppoe_padi() ->
    hexstr2bin("11090000003101010005737061726301"
	       "0300041004e1d80105001c00000de901"
	       "164369726375697449442061746d2030"
	       "2f323a312e3332").

pppoe_pado() ->
    hexstr2bin("11070000002a010300041004e1d80101"
	       "00057370617263010200093d4f70656e"
	       "424e473d01040004deadbeef00000000").

pppoe_padr() ->
    hexstr2bin("11190000003901010005737061726301"
	       "0300041004e1d801040004deadbeef01"
	       "05001c00000de9011643697263756974"
	       "49442061746d20302f323a312e3332").

pppoe_pads() ->
    hexstr2bin("11650002002201010005737061726301"
	       "0300041004e1d8010200093d4f70656e"
	       "424e473d00000000000000000000").

% hexstr2bin
hexstr2bin(S) ->
    list_to_binary(hexstr2list(S)).

hexstr2list([X,Y|T]) ->
    [mkint(X)*16 + mkint(Y) | hexstr2list(T)];
hexstr2list([]) ->
    [].

mkint(C) when $0 =< C, C =< $9 ->
    C - $0;
mkint(C) when $A =< C, C =< $F ->
    C - $A + 10;
mkint(C) when $a =< C, C =< $f ->
    C - $a + 10.

%%--------------------------------------------------------------------
%% @spec suite() -> Info
%% Info = [tuple()]
%% @end
%%--------------------------------------------------------------------
suite() ->
	[{timetrap,{seconds,30}}].

test_pppoe_padt(_Config) ->
    PPPoE = pppoe_frame:decode(pppoe_padt()),
    ct:pal("PPPoE: ~p~n", [PPPoE]),
    ok.

test_pppoe_padi(_Config) ->
    PPPoE = pppoe_frame:decode(pppoe_padi()),
    ct:pal("PPPoE: ~p~n", [PPPoE]),
    ok.

test_pppoe_pado(_Config) ->
    PPPoE = pppoe_frame:decode(pppoe_pado()),
    ct:pal("PPPoE: ~p~n", [PPPoE]),
    ok.

test_pppoe_padr(_Config) ->
    PPPoE = pppoe_frame:decode(pppoe_padr()),
    ct:pal("PPPoE: ~p~n", [PPPoE]),
    ok.

test_pppoe_pads(_Config) ->
    PPPoE = pppoe_frame:decode(pppoe_pads()),
    ct:pal("PPPoE: ~p~n", [PPPoE]),
    ok.

all() -> 
	[test_pppoe_padt, test_pppoe_padi, test_pppoe_pado,
	 test_pppoe_padr, test_pppoe_pads].

init_per_suite(Config) ->
	Config.

end_per_suite(_Config) ->
	ok.

