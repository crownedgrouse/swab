PROJECT = $(notdir $(shell pwd))
ERLC_OPTS = +debug_info +warn_export_all +warn_export_vars +warn_shadow_vars +warn_obsolete_guard

EUNIT_ERL_OPTS = -pa $(shell pwd)/priv -pa $(shell pwd)/ebin

include erlang.mk

clean:: 
	-@find . -type f -name \*~ -delete
