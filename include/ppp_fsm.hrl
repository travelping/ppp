-type ppp_option() :: term().

-record(fsm_config, {
	  silent = false		:: boolean(),
	  passive = false		:: boolean(),
	  term_restart_count = 0	:: integer(),
	  conf_restart_count = 0	:: integer(),
	  failure_count	= 0		:: integer(),
	  restart_timeout = 0		:: integer()
	 }).
