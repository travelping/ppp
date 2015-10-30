%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

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
    ppp_link:accounting_on(),
    ppp_sup:start_link().

stop(_State) ->
    ok.
