LUA ?= luajit
PYTHON ?= python3

.PHONY: test mock
test:
	$(LUA) tests/test_jev.lua
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

mock:
	$(PYTHON) tools/mock_jev.py
