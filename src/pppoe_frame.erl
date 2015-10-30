%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

-module(pppoe_frame).

-export([decode/1, encode/1]).

-compile(bin_opt_info).
-compile(inline).

-define(PPPOE_VERSION, 1).
-define(PPPOE_TYPE, 1).

-define(PPPOE_PPP, 16#00).
-define(PPPOE_PADO, 16#07).
-define(PPPOE_PADI, 16#09).
-define(PPPOE_PADR, 16#19).
-define(PPPOE_PADS, 16#65).
-define(PPPOE_PADT, 16#a7).

-define(END_OF_LIST,		16#0000).
-define(SERVICE_NAME,		16#0101).
-define(AC_NAME,		16#0102).
-define(HOST_UNIQ,		16#0103).
-define(AC_COOKIE,		16#0104).
-define(VENDOR_SPECIFIC,	16#0105).
-define(RELAY_SESSION_ID,	16#0110).
-define(SERVICE_NAME_ERROR,	16#0201).
-define(AC_SYSTEM_ERROR,	16#0202).
-define(GENERIC_ERROR,		16#0203).

tag(?END_OF_LIST)		-> 'End-Of-List';
tag(?SERVICE_NAME)		-> 'Service-Name';
tag(?AC_NAME)			-> 'AC-Name';
tag(?HOST_UNIQ)			-> 'Host-Uniq';
tag(?AC_COOKIE)			-> 'AC-Cookie';
tag(?VENDOR_SPECIFIC)		-> 'Vendor-Specific';
tag(?RELAY_SESSION_ID)		-> 'Relay-Session-Id';
tag(?SERVICE_NAME_ERROR)	-> 'Service-Name-Error';
tag(?AC_SYSTEM_ERROR)		-> 'AC-System-Error';
tag(?GENERIC_ERROR)		-> 'Generic-Error';

tag('End-Of-List')		-> ?END_OF_LIST;
tag('Service-Name')		-> ?SERVICE_NAME;
tag('AC-Name')			-> ?AC_NAME;
tag('Host-Uniq')		-> ?HOST_UNIQ;
tag('AC-Cookie')		-> ?AC_COOKIE;
tag('Vendor-Specific')		-> ?VENDOR_SPECIFIC;
tag('Relay-Session-Id')		-> ?RELAY_SESSION_ID;
tag('Service-Name-Error')	-> ?SERVICE_NAME_ERROR;
tag('AC-System-Error')		-> ?AC_SYSTEM_ERROR;
tag('Generic-Error')		-> ?GENERIC_ERROR;

tag(X) when is_integer(X)	-> X.

dslf_tag(16#01) -> 'ADSL-Agent-Circuit-Id';
dslf_tag(16#02) -> 'ADSL-Agent-Remote-Id';
dslf_tag(16#81) -> 'Actual-Data-Rate-Upstream';
dslf_tag(16#82) -> 'Actual-Data-Rate-Downstream';
dslf_tag(16#83) -> 'Minimum-Data-Rate-Upstream';
dslf_tag(16#84) -> 'Minimum-Data-Rate-Downstream';
dslf_tag(16#85) -> 'Attainable-Data-Rate-Upstream';
dslf_tag(16#86) -> 'Attainable-Data-Rate-Downstream';
dslf_tag(16#87) -> 'Maximum-Data-Rate-Upstream';
dslf_tag(16#88) -> 'Maximum-Data-Rate-Downstream';
dslf_tag(16#89) -> 'Minimum-Data-Rate-Upstream-Low-Power';
dslf_tag(16#8a) -> 'Minimum-Data-Rate-Downstream-Low-Power';
dslf_tag(16#8b) -> 'Maximum-Interleaving-Delay-Upstream';
dslf_tag(16#8c) -> 'Actual-Interleaving-Delay-Upstream';
dslf_tag(16#8d) -> 'Maximum-Interleaving-Delay-Downstream';
dslf_tag(16#8e) -> 'Actual-Interleaving-Delay-Downstream';

dslf_tag(X)				-> X.

pppoe_code(?PPPOE_PPP) -> ppp;
pppoe_code(?PPPOE_PADO) -> pado;
pppoe_code(?PPPOE_PADI) -> padi;
pppoe_code(?PPPOE_PADR) -> padr;
pppoe_code(?PPPOE_PADS) -> pads;
pppoe_code(?PPPOE_PADT) -> padt;

pppoe_code(ppp) -> ?PPPOE_PPP;
pppoe_code(pado) -> ?PPPOE_PADO;
pppoe_code(padi) -> ?PPPOE_PADI;
pppoe_code(padr) -> ?PPPOE_PADR;
pppoe_code(pads) -> ?PPPOE_PADS;
pppoe_code(padt) -> ?PPPOE_PADT.


decode(<<Version:4/integer, Type:4/integer, Code:8/integer,
	 SessionId:16/integer, Length:16/integer, PayLoad:Length/binary, _Rest/binary>>)
  when ?PPPOE_VERSION == Version,
       ?PPPOE_TYPE == Type ->
    decode(pppoe_code(Code), SessionId, PayLoad).

decode(ppp, SessionId, PayLoad) ->
    {ppp, SessionId, PayLoad};

decode(Code, SessionId, PayLoad) ->
    {Code, SessionId, decode_tlv(PayLoad)}.

decode_dslf_tags(<<>>, Acc) ->
    Acc;
decode_dslf_tags(<<16#fe:8, 0:8>>, Acc) ->
    Acc;
decode_dslf_tags(<<Tag:8, Length:8, Value:Length/bytes, Rest/binary>>, Acc) ->
    decode_dslf_tags(Rest, [{dslf, {dslf_tag(Tag), Value}}|Acc]).

decode_tag(<<Vendor:32/integer, Value/binary>>, 'Vendor-Specific')
  when Vendor == 16#DE9 ->
    decode_dslf_tags(Value, []);
decode_tag(<<Vendor:32/integer, Value/binary>>, Tag = 'Vendor-Specific') ->
    {Tag, Vendor, Value};
decode_tag(Value, Tag) ->
    {Tag, Value}.

decode_tlv(<<>>, Acc) ->
    lists:reverse(lists:flatten(Acc));
decode_tlv(<<0:16/integer, 0:16/integer>>, Acc) ->
    %% End-Of-List
    lists:reverse(lists:flatten(Acc));
decode_tlv(<<Tag:16/integer, Length:16/integer, Value:Length/binary, Rest/binary>>, Acc) ->
    decode_tlv(Rest, [decode_tag(Value, tag(Tag))|Acc]).

decode_tlv(Bin) ->
    decode_tlv(Bin, []).

encode({ppp, SessionId, PayLoad}) ->
    <<?PPPOE_VERSION:4, ?PPPOE_TYPE:4/integer, (pppoe_code(ppp)):8,
      SessionId:16, (size(PayLoad)):16, PayLoad/binary>>;
encode({Code, SessionId, TLV})
  when Code == pado; Code == padi; Code == padr;
       Code == pads; Code == padt ->
    PayLoad = encode_tlv(TLV, <<>>),
    <<?PPPOE_VERSION:4, ?PPPOE_TYPE:4/integer, (pppoe_code(Code)):8,
      SessionId:16, (size(PayLoad)):16, PayLoad/binary>>.

encode_tlv([], B) ->
    B;
encode_tlv([{Tag, Value}|T], B) ->
    encode_tlv(T, << B/binary, (tag(Tag)):16, (size(Value)):16/integer, Value/binary>>);
encode_tlv([TLVs|T], B) when is_list(TLVs) ->
    encode_tlv(T, encode_tlv(TLVs, B)).

