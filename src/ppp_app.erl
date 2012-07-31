%% Copyright 2010-2012, Travelping GmbH <info@travelping.com>

-module(ppp_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    ppp_sup:start_link().

stop(_State) ->
    ok.