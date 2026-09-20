LUA ?= luajit
PYTHON ?= python3

.PHONY: test smoke mock
test:
	$(LUA) tests/test_jev.lua
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

smoke:
	@for scenario in disabled standalone gpt observe; do \
		$(PYTHON) tests/smoke_rspamd.py --scenario "$$scenario" || exit $$?; \
	done

mock:
	$(PYTHON) tools/mock_jev.py
