%% Copyright 2010-2012, Travelping GmbH <info@travelping.com>

-module(ppp_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    eradius_dict:load_tables([dictionary, dictionary_alcatel_sr, dictionary_rfc4679]),
    ppp_sup:start_link().

stop(_State) ->
    ok.
