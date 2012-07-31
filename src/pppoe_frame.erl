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


decode_tlv(<<>>, Acc) ->
    lists:reverse(Acc);
decode_tlv(<<Tag:16/integer, Length:16/integer, Value:Length/binary, Rest/binary>>, Acc) ->
    decode_tlv(Rest, [{Tag, Value}|Acc]).

decode_tlv(Bin) ->
    decode_tlv(Bin, []).

encode({ppp, SessionId, PayLoad}) ->
    <<?PPPOE_VERSION:4, ?PPPOE_TYPE:4/integer, (pppoe_code(ppp)):8,
      SessionId:16, (size(PayLoad)):16, PayLoad/binary>>;
encode({Code, SessionId, TLV})
  when Code == pado; Code == padi; Code == padr;
       Code == pads; Code == padt ->
    PayLoad = encode_tlv(TLV),
    <<?PPPOE_VERSION:4, ?PPPOE_TYPE:4/integer, (pppoe_code(Code)):8,
      SessionId:16, (size(PayLoad)):16, PayLoad/binary>>.

encode_tlv(Tag, Value) ->
    <<Tag:16, (size(Value)):16/integer, Value/binary>>.

encode_tlv(TLV) ->
    << << (encode_tlv(Tag, Value))/binary >> || {Tag, Value} <- TLV>>.

