-type rxtx_counter() :: {non_neg_integer(), non_neg_integer()}.

-record(ppp_stats, {
	  packet_count	:: rxtx_counter(),			%% Number of packets.
	  byte_count	:: rxtx_counter()			%% Number of bytes.
}).
