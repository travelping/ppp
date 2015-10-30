%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

-record(epdisc, {
	  class = 0			:: integer(),
	  address = <<>>		:: binary()
}).

-record(lcp_opts, {
	  neg_mru = false		:: boolean(),			%% Negotiate the MRU?
	  neg_asyncmap = false		:: boolean(),			%% Negotiate the async map?
	  neg_auth = []			:: atom() | [atom()],		%% Ask for UPAP, CHAP (and which MD types (hashing algorithm)) and/or EAP authentication?
	  neg_magicnumber = false	:: boolean(),			%% Ask for magic number?
	  neg_pcompression = false	:: boolean(),			%% HDLC Protocol Field Compression?
	  neg_accompression = false	:: boolean(),			%% HDLC Address/Control Field Compression?
	  neg_lqr = false		:: boolean(),			%% Negotiate use of Link Quality Reports
	  neg_cbcp = false		:: boolean(),			%% Negotiate use of CBCP
	  neg_mrru = false		:: boolean(),			%% negotiate multilink MRRU
	  neg_ssnhf = false		:: boolean(),			%% negotiate short sequence numbers
	  neg_endpoint  = false		:: boolean(),			%% negotiate endpoint discriminator
	  mru = 0			:: integer(),			%% Value of MRU
	  mrru = 0			:: integer(),			%% Value of MRRU, and multilink enable
	  asyncmap = 0			:: integer(),			%% Value of async map
	  magicnumber = 0		:: integer(),
	  numloops = 0			:: integer(),			%% Number of loops during magic number neg.
	  lqr_period = 0		:: integer(),			%% Reporting period for LQR 1/100ths second
	  endpoint = #epdisc{}		:: #epdisc{}			%% endpoint discriminator
}).
