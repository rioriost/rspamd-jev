-- Rspamd/UCL boundary doubles; run real daemon smoke tests before deployment.
local registered, records, requests, options, logs, clock, gpt_config
local reply, parse_ok, schedule_ok, request_hook
local utf8_replacements
local tokens = {}
local serial = 0
local function encode(object)
  serial = serial + 1
  local token = 'json-token-' .. serial
  tokens[token] = object
  return token
end
package.preload.rspamd_http = function()
  return {request = function(params)
    table.insert(requests, params)
    if request_hook then request_hook(params) end
    return schedule_ok
  end}
end
package.preload.rspamd_logger = function()
  local function log(_, format, ...)
    table.insert(logs, {format, ...})
    if format == 'JEV_EVAL %s' then table.insert(records, tokens[(...)]) end
  end
  return {infox = log, warnx = log, errx = log}
end
package.preload.rspamd_util = function()
  return {
    get_time = function() return clock end,
    is_valid_utf8 = function(value) return utf8_replacements[tostring(value)] == nil end,
    to_utf8 = function(value, charset)
      assert(charset == 'UTF-8')
      return utf8_replacements[tostring(value)]
    end,
  }
end
package.preload.lua_util = function()
  return {disable_module = function() end}
end
package.preload.ucl = function()
  local function parser()
    return {
      parse_string = function() return parse_ok end,
      get_object = function() return reply end,
    }
  end
  return {
    to_format = encode,
    untrusted_parser = parser,
    parser = function(flags)
      assert(flags == 100, 'legacy parser must disable macros and file variables')
      return parser()
    end,
  }
end

local function valid_reply()
  return {
    model = 'jev-1.13.0',
    answers = {category = {
      type = 'choice', choice = 'spam', confidence = 0.99,
      probabilities = {ham = 0.005, spam = 0.99, phishing = 0.005},
    }},
    usage = {input_tokens = 100, output_tokens = 10},
  }
end

local function setup(overrides)
  registered, records, requests, logs, clock = {}, {}, {}, {}, 100
  reply, parse_ok, schedule_ok, request_hook = valid_reply(), true, true, nil
  utf8_replacements = {}
  options = {enabled = true, sample_rate = 1}
  gpt_config = {type = 'ollama', model = 'baseline-model'}
  for key, value in pairs(overrides or {}) do options[key] = value end
  rspamd_config = {
    get_all_opt = function(_, name)
      if name == 'jev' then return options end
      if name == 'gpt' then return gpt_config end
    end,
    register_symbol = function(_, symbol)
      registered[symbol.name] = symbol
      return symbol.name
    end,
    register_dependency = function(_, name, dependency)
      registered[name].dependency = dependency
    end,
  }
  dofile('rspamd/jev.lua')
end

local function task()
  local t = {
    cache = {}, inserted = {},
    headers = {Subject = 'Synthetic message', From = 'test@example.test', ['Reply-To'] = 'reply@example.test'},
    symbols = {GPT_HAM = {{options = {'0.1'}, score = -1.6}}},
    recipients = {{domain = 'example.test'}},
    size = 100,
    digest = string.rep('a', 32),
    text = 'Synthetic body',
    urls = {}, parts = {},
    metric = {score = 2.5, action = 'no action'},
  }
  function t:get_header(name) return self.headers[name] end
  function t:get_user() return self.user end
  function t:get_recipients() return self.recipients end
  function t:get_size() return self.size end
  function t:get_digest() return self.digest end
  function t:cache_set(key, value) self.cache[key] = value end
  function t:cache_get(key) return self.cache[key] end
  function t:get_symbol(name) return self.symbols[name] end
  function t:has_symbol(name) return self.symbols[name] ~= nil end
  function t:get_metric_result() return self.metric end
  function t:get_urls() return self.urls end
  function t:get_parts() return self.parts end
  function t:get_text_parts()
    return {{
      get_content = function() return self.text end,
      is_empty = function() return self.text == '' end,
      is_html = function() return false end,
      get_mimepart = function() return {is_attachment = function() return false end} end,
    }}
  end
  function t:insert_result(symbol, weight, option)
    assert(weight == 0, 'shadow result has nonzero weight')
    table.insert(self.inserted, {symbol, weight, option})
  end
  function t:set_pre_result() error('must never change action') end
  function t:set_flag() error('must never set learning flags') end
  return t
end
local function run(t)
  registered.JEV_CHECK.callback(t)
  return t:cache_get('jev_eval')
end
local function finish(err, code)
  clock = clock + 0.125
  requests[#requests].callback(err, code or 200, 'response')
end
local function log(t) registered.JEV_LOG.callback(t) end
local tests = {}
local function test(name, fn) tests[#tests + 1] = {name, fn} end

test('disabled loads without credentials or registrations', function()
  setup({enabled = false, mode = 'live'})
  assert(next(registered) == nil)
end)
test('safe settings and explicit dependency', function()
  setup({require_gpt = true})
  assert(registered.JEV_CHECK.dependency == 'GPT_CHECK')
  assert(registered.JEV_LOG.type == 'idempotent')
  assert(registered.JEV_LOG.dependency == nil)
  for _, name in ipairs({'SPAM', 'HAM', 'PHISHING', 'UNCERTAIN', 'ERROR'}) do
    assert(registered['JEV_' .. name].score == 0)
    assert(registered['JEV_' .. name].flags == 'nostat')
  end
end)
test('configuration rejects unsafe modes and invalid limits', function()
  for _, override in ipairs({
    {mode = 'other'}, {mode = 'live'}, {url = 'http://evil.test/v1/systemone'},
    {mode = 'live', allow_external = true, recipient_domains = {'example.test'},
      url = 'https://evil.test/v1/systemone'},
    {mode = 'live', allow_external = true, recipient_domains = {'example.test'},
      url = 'https://api.typesafe.ai/v1/systemone', api_key_file = 'relative-key'},
    {model = 'jev-latest'}, {sample_rate = 1.1}, {sample_rate = 0/0},
    {timeout = -1}, {max_inflight = 0}, {max_urls = 1.5},
    {unknown = true}, {require_gpt = 'true'}, {recipient_domains = {'*'}},
  }) do
    local ok, err = pcall(setup, override)
    assert(not ok and tostring(err):find('jev:'), 'configuration unexpectedly accepted')
  end
end)
test('live activation validates and reads secret without logging it', function()
  local old_open = io.open
  io.open = function()
    return {read = function() return 'test-secret\n' end, close = function() end}
  end
  local ok, err = pcall(setup, {mode = 'live', allow_external = true,
    api_key_file = '/test-only/jev-api-key',
    url = 'https://api.typesafe.ai/v1/systemone', recipient_domains = {'example.test'}})
  io.open = old_open
  assert(ok, err)
  local t = task()
  run(t)
  assert(requests[1].headers.Authorization == 'Bearer test-secret')
  finish()
  log(t)
  assert(records[1].mode == 'live')
  for _, entry in ipairs(logs) do
    for _, value in ipairs(entry) do assert(not tostring(value):find('test%-secret')) end
  end
end)
test('request shape, result, final metric and baseline are paired', function()
  setup()
  local t = task()
  local r = run(t)
  local p = requests[1]
  assert(p.no_ssl_verify == false and p.timeout == 1.5 and p.max_size == 16384)
  assert(p.headers.Authorization == 'Bearer mock-only')
  local body = tokens[p.body]
  assert(body.messages == nil and body.questions.category.type == 'choice')
  assert(body.state.subject == t.headers.Subject and body.state.text_parts[1].text == t.text)
  assert(body.state.GPT_HAM == nil and body.state.score == nil)
  finish()
  assert(r.status == 'ok' and r.jev.decision == 'spam' and r.latency_ms == 125)
  assert(t.inserted[1][1] == 'JEV_SPAM')
  t.metric.score = 3
  log(t)
  assert(records[1].rspamd_score == 3 and records[1].rspamd_action == 'no action')
  assert(records[1].baseline.verdict == 'ham' and records[1].baseline.probability == 0.1)
  assert(records[1].state == nil and records[1].subject == nil)
end)
test('uncertainty is not ham', function()
  setup()
  reply.answers.category.confidence = 0.2
  local t = task()
  local r = run(t)
  finish()
  assert(r.jev.choice == 'spam' and r.jev.decision == 'uncertain')
  assert(t.inserted[1][1] == 'JEV_UNCERTAIN')
end)
test('probability threshold is independent of confidence', function()
  setup()
  reply.answers.category.probabilities = {ham = 0.2, spam = 0.7, phishing = 0.1}
  local r = run(task())
  finish()
  assert(r.jev.decision == 'uncertain')
end)
test('privacy and selection skips issue no HTTP', function()
  for _, case in ipairs({
    {reason = 'authenticated', change = function(t) t.user = 'user' end},
    {reason = 'recipient_domain', opts = {recipient_domains = {'other.test'}}},
    {reason = 'recipient_domain', opts = {recipient_domains = {'example.test'}},
      change = function(t) t.recipients[2] = {domain = 'other.test'} end},
    {reason = 'no_smtp_recipients', opts = {recipient_domains = {'example.test'}},
      change = function(t) t.recipients = {} end},
    {reason = 'no_gpt_result', opts = {require_gpt = true}, change = function(t) t.symbols = {} end},
    {reason = 'message_too_large', change = function(t) t.size = 1048577 end},
    {reason = 'sample', opts = {sample_rate = 0}},
    {reason = 'no_text_evidence', change = function(t) t.text = ''; t.headers.Subject = '' end},
    {reason = 'request_too_large', opts = {max_request_bytes = 1}},
  }) do
    setup(case.opts)
    local t = task()
    if case.change then case.change(t) end
    local r = run(t)
    assert(r.status == 'skipped' and r.reason == case.reason, case.reason)
    assert(#requests == 0 and #t.inserted == 0)
    log(t)
    assert(#records == 1)
  end
end)
test('UTF-8 truncation and attachment metadata do not expose attachment contents', function()
  setup({max_body_bytes = 5, max_urls = 1, max_attachments = 1})
  local t = task()
  t.text = '\227\129\130\227\129\132' -- two UTF-8 codepoints
  local function url()
    return {
      get_text = function() return 'https://example.test/link' end,
      get_host = function() return 'example.test' end,
      get_visible = function() return 'View invoice' end,
    }
  end
  t.urls = {url(), url()}
  t.parts = {{
    is_attachment = function() return true end,
    get_filename = function() return 'invoice.pdf' end,
    get_type = function() return 'application', 'pdf' end,
    get_content = function() error('must not read attachments') end,
  }}
  t.symbols.R_DKIM_ALLOW = {{}}
  run(t)
  local state = tokens[requests[1].body].state
  assert(#state.text_parts[1].text == 3 and state.truncated)
  assert(#state.urls == 1 and state.urls[1].visible == 'View invoice')
  assert(state.attachments[1].content_type == 'application/pdf')
  assert(state.verified_auth_symbols[1] == 'R_DKIM_ALLOW')
end)
test('repairs malformed evidence before UTF-8-safe byte limits', function()
  setup({max_body_bytes = 5})
  local t = task()
  local broken = 'x\227\129'
  local repaired = 'x\239\191\189'
  utf8_replacements[broken] = repaired
  t.headers.Subject, t.headers.From, t.headers['Reply-To'] = broken, broken, broken
  t.text = broken
  t.urls = {{
    get_text = function() return broken end,
    get_host = function() return broken end,
    get_visible = function() return broken end,
  }}
  t.parts = {{
    is_attachment = function() return true end,
    get_filename = function() return broken end,
    get_type = function() return 'application', 'pdf' end,
  }}
  local r = run(t)
  local state = tokens[requests[1].body].state
  assert(state.subject == repaired and state.from == repaired and state.reply_to == repaired)
  assert(state.text_parts[1].text == repaired and #state.text_parts[1].text <= 5)
  assert(state.urls[1].visible == repaired and state.attachments[1].filename == repaired)
  assert(r.utf8_repaired_fields == 8 and r.evidence_version == 'email-evidence-v2')
  finish()
  assert(r.status == 'ok')
end)
test('conversion failure is an explicit local error, never an external request', function()
  setup()
  local t = task()
  t.text = 'bad\255'
  utf8_replacements[t.text] = false
  local r = run(t)
  assert(r.status == 'error' and r.reason == 'invalid_utf8' and #requests == 0)
  assert(t.inserted[1][1] == 'JEV_ERROR')
  assert(run(task()).status == 'pending', 'bad evidence must not open the worker circuit')
end)
test('repaired codepoints cannot exceed the body byte budget', function()
  setup({max_body_bytes = 3})
  local t = task()
  t.text = 'a\255'
  utf8_replacements[t.text] = 'a\239\191\189'
  local r = run(t)
  assert(tokens[requests[1].body].state.text_parts[1].text == 'a')
  assert(r.truncated and r.utf8_repaired_fields == 1)
end)
test('final serialized UTF-8 validation prevents malformed requests', function()
  setup()
  local ucl = require 'ucl'
  local original = ucl.to_format
  utf8_replacements['bad\255json'] = false
  ucl.to_format = function() return 'bad\255json' end
  local t = task()
  local r = run(t)
  ucl.to_format = original
  assert(r.status == 'error' and r.reason == 'invalid_utf8' and #requests == 0)
  assert(t.inserted[1][1] == 'JEV_ERROR')
end)
test('API error classes are allowlisted and never include upstream detail', function()
  for _, case in ipairs({
    {400, 'body_parse_error', 'There was an error parsing the body'},
    {400, 'bad_request', 'private mail content or credentials'},
    {401, 'unauthorized'}, {403, 'forbidden'}, {413, 'request_too_large'},
    {422, 'validation_error'}, {429, 'rate_limited'}, {500, 'server_error'},
    {529, 'overloaded'}, {404, 'http_error'},
  }) do
    setup()
    reply = {detail = case[3] or 'private mail content or credentials'}
    local t = task()
    local r = run(t)
    finish(nil, case[1])
    log(t)
    assert(r.reason == 'http_status' and r.api_error == case[2])
    for _, entry in ipairs(logs) do
      for _, value in ipairs(entry) do
        assert(not tostring(value):find('private mail content'))
      end
    end
    assert(run(task()).reason == 'circuit_open')
  end
  setup()
  parse_ok = false
  local r = run(task())
  finish(nil, 400)
  assert(r.api_error == 'bad_request')
end)
test('malformed and invalid API outputs are errors, never classifications', function()
  for _, mutate in ipairs({
    function() parse_ok = false end,
    function() reply.model = 'jev-latest' end,
    function() reply.answers = {} end,
    function() reply.answers.category.choice = 'other' end,
    function() reply.answers.category.confidence = 0/0 end,
    function() reply.answers.category.probabilities.spam = -1 end,
    function() reply.answers.category.probabilities.phishing = nil end,
    function() reply.answers.category.probabilities.extra = 0 end,
    function() reply.answers.category.probabilities.ham = 0.5 end,
    function() reply.answers.category.choice = 'ham' end,
    function() reply.usage = nil end,
    function() reply.usage.input_tokens = math.huge end,
  }) do
    setup()
    mutate()
    local t = task()
    local r = run(t)
    finish()
    assert(r.status == 'error' and r.jev == nil)
    assert(t.inserted[1][1] == 'JEV_ERROR')
    assert(run(task()).reason == 'circuit_open')
  end
end)
test('transport, HTTP errors, schedule failure open circuit without retry', function()
  for _, case in ipairs({{err = 'secret in upstream error'}, {code = 401}, {code = 429},
      {code = 500}, {code = 529}, {schedule = false}}) do
    setup()
    if case.schedule == false then schedule_ok = false end
    local r = run(task())
    if case.schedule ~= false then finish(case.err, case.code) end
    assert(r.status == 'error' and r.jev == nil and #requests == 1)
    assert(run(task()).reason == 'circuit_open')
    for _, entry in ipairs(logs) do
      for _, value in ipairs(entry) do assert(not tostring(value):find('secret in upstream')) end
    end
    clock = clock + 61
    schedule_ok = true
    assert(run(task()).status == 'pending')
  end
end)
test('bounded requests and callback releases inflight slot exactly once', function()
  setup({max_inflight = 1})
  run(task())
  clock = clock + 2
  assert(run(task()).reason == 'inflight_limit')
  finish()
  finish()
  assert(run(task()).status == 'pending')
  clock = clock + 2
  assert(run(task()).reason == 'inflight_limit')
end)
test('rate limiting is independent of inflight limit', function()
  setup()
  run(task())
  assert(run(task()).reason == 'rate_limit')
end)
test('default standalone operation needs no GPT module or verdict', function()
  setup()
  gpt_config = nil
  assert(registered.JEV_CHECK.dependency == nil)
  local t = task()
  t.symbols = {}
  local r = run(t)
  finish()
  log(t)
  assert(r.status == 'ok' and r.baseline.verdict == 'not_observed')
  assert(r.require_gpt == false and r.baseline.provider == nil)
end)
test('optional baseline is collected after all postfilters finish', function()
  setup()
  gpt_config = {type = 'openai', model = 'another-provider-model'}
  local t = task()
  t.symbols = {}
  local r = run(t)
  finish()
  t.symbols.GPT_SPAM = {{options = {'0.95'}}}
  log(t)
  assert(r.baseline.verdict == 'spam' and r.baseline.probability == 0.95)
  assert(r.baseline.provider == 'openai' and r.require_gpt == false)
end)
test('comparison selection preserves explicit require_gpt behavior', function()
  setup({require_gpt = true})
  local t = task()
  local r = run(t)
  finish()
  log(t)
  assert(r.status == 'ok' and r.require_gpt == true and r.baseline.verdict == 'ham')
end)
test('final logger reports incomplete requests explicitly', function()
  setup()
  local t = task()
  run(t)
  log(t)
  assert(records[1].status == 'error' and records[1].reason == 'incomplete')
end)
test('legacy UCL uses explicit safe flags', function()
  local ucl = require 'ucl'
  local original = ucl.untrusted_parser
  ucl.untrusted_parser = nil
  setup()
  local r = run(task())
  finish()
  ucl.untrusted_parser = original
  assert(r.status == 'ok')
end)

for _, entry in ipairs(tests) do
  local ok, err = pcall(entry[2])
  if not ok then io.stderr:write('FAIL: ' .. entry[1] .. ': ' .. tostring(err) .. '\n'); os.exit(1) end
  print('PASS: ' .. entry[1])
end
print(string.format('%d Lua tests passed', #tests))
