%% Copyright 2010-2012, Travelping GmbH <info@travelping.com>
-module(ppp_link_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).
-export([new/3]).

%% Supervisor callbacks
-export([init/1]).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

new(TransportModule, TransportRef, Config) ->
    supervisor:start_child(?MODULE, [TransportModule, TransportRef, Config]).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    {ok, {{simple_one_for_one, 0, 1},
          [{ppp_link, {ppp_link, start_link, []},
            temporary, brutal_kill, worker, [ppp_link]}]}}.
