PROJECT = $(notdir $(shell pwd))
ERLC_OPTS = +debug_info +warn_export_all +warn_export_vars +warn_shadow_vars +warn_obsolete_guard
CT_SUITES = swab
#EDOC_OPTS = {private, true}

include erlang.mk

eunit: app
	erl -noshell -pa `pwd`/ebin -pa `pwd`/priv -eval 'eunit:test(swab, [verbose])' -s init stop

clean:: 
	-@find . -type f -name \*~ -delete
