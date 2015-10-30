%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

-type rxtx_counter() :: {non_neg_integer(), non_neg_integer()}.

-record(ppp_stats, {
	  packet_count	:: rxtx_counter(),			%% Number of packets.
	  byte_count	:: rxtx_counter()			%% Number of bytes.
}).
