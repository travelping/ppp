%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

-record(ipcp_opts, {
    neg_addr = false		:: boolean(),			%% Negotiate IP Address?
    req_addr = false		:: boolean(),			%% Ask peer to send IP address?
    accept_local = false	:: boolean(),			%% accept peer's value for ouraddr
    accept_remote = false	:: boolean(),			%% accept peer's value for hisaddr
    usepeerdns = false		:: boolean(),			%% Ask peer to send DNS address?
    req_dns1 = false		:: boolean(),			%% Ask peer to send primary DNS address?
    req_dns2 = false		:: boolean(),			%% Ask peer to send secondary DNS address?
    neg_vj = false		:: boolean(),			%% Van Jacobson Compression?
    vj_protocol = vjc		:: atom(),			%% protocol value to use in VJ option
    maxslotindex = 0		:: integer(),			%% values for RFC1332 VJ compression neg.
    vjcflag = false		:: boolean(),			%% Enable/Disable VJ connection-ID compression
    ouraddr = <<0,0,0,0>>	:: binary(),			%% Addresses in NETWORK BYTE ORDER
    hisaddr = <<0,0,0,0>>	:: binary(),
    dnsaddr1 = <<0,0,0,0>>	:: binary(),			%% Primary and secondary MS DNS entries
    dnsaddr2 = <<0,0,0,0>>	:: binary(),
    winsaddr1 = <<0,0,0,0>>	:: binary(),			%% Primary and secondary MS WINS entries
    winsaddr2 = <<0,0,0,0>>	:: binary()
}).
