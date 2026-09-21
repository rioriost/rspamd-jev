-- Real Rspamd UTF-8 conversion and UCL serialization with synthetic URL fields.
local util = require 'rspamd_util'
local ucl = require 'ucl'
local http = require 'rspamd_http'
local logger = require 'rspamd_logger'
local native_config, infox = rspamd_config, logger.infox
logger.infox = function(_, format, ...) infox(native_config, format, ...) end
local registered, captured
http.request = function(params)
  captured = params
  assert(util.is_valid_utf8(params.body), 'serialized request must be valid UTF-8')
  return true
end
rspamd_config = {
  get_all_opt = function(_, name)
    if name == 'jev' then return {enabled = true, sample_rate = 1} end
    return {}
  end,
  register_symbol = function(_, symbol)
    registered[symbol.name] = symbol
    return symbol.name
  end,
}
for _, broken in ipairs({
  'link\255', 'link\227\129', 'link\192\175', 'link\237\160\128',
  'link\244\144\128\128', string.rep('x', 255) .. '\255',
}) do
  assert(not util.is_valid_utf8(broken), 'fixture must be malformed')
  registered, captured = {}, nil
  dofile('rspamd/jev.lua')
  local cache = {}
  local task = {
    get_user = function() end,
    get_size = function() return 1024 end,
    get_digest = function() return string.rep('a', 32) end,
    get_header = function() return '' end,
    get_text_parts = function() return {} end,
    get_parts = function() return {} end,
    has_symbol = function() return false end,
    cache_set = function(_, key, value) cache[key] = value end,
    get_urls = function()
      return {{
        get_text = function() return 'https://example.test/fixture' end,
        get_host = function() return 'example.test' end,
        get_visible = function() return broken end,
      }}
    end,
  }
  registered.JEV_CHECK.callback(task)
  assert(captured, 'synthetic request was not captured')
  local parser = ucl.parser()
  assert(parser:parse_string(captured.body))
  local visible = parser:get_object().state.urls[1].visible
  assert(util.is_valid_utf8(visible) and #visible <= 256)
  assert(cache.jev_eval.utf8_repaired_fields == 1)
  assert(cache.jev_eval.evidence_version == 'email-evidence-v2')
end
print('Native UTF-8 regression passed: 6 malformed URL fields repaired within byte limits.')
