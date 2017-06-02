Erlang PPP library and deamon
=============================
[![Build Status][travis badge]][travis]
[![Coverage Status][coveralls badge]][coveralls]
[![Erlang Versions][erlang version badge]][travis]

This library implements a PPP packet de/encoder and fully implements the
[RFC 1661](https://tools.ietf.org/html/rfc1661) PPP state-machine.

BUILDING
--------

*The minimum supported Erlang version is 19.0.*

Using rebar3:

    # rebar3 compile

<!-- Badges -->
[travis]: https://travis-ci.org/travelping/ppp
[travis badge]: https://img.shields.io/travis/travelping/ppp/master.svg?style=flat-square
[coveralls]: https://coveralls.io/github/travelping/ppp
[coveralls badge]: https://img.shields.io/coveralls/travelping/ppp/master.svg?style=flat-square
[erlang version badge]: https://img.shields.io/badge/erlang-R19.1%20to%2019.3-blue.svg?style=flat-square