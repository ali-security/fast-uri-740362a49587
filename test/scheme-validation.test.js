'use strict'

const test = require('tape')
const fastURI = require('..')

const MALFORMED_SCHEME_ERROR = 'URI scheme is malformed.'

// U+212A KELVIN SIGN, built from its code point because it is indistinguishable
// from an ASCII "K" in a source listing. Together with U+017F LATIN SMALL LETTER
// LONG S below it guards the scheme pattern against Unicode case folding: both
// fold onto an ASCII letter ("k" and "s"), so a case-insensitive pattern would
// accept them as the start of a scheme.
const KELVIN_SIGN = String.fromCharCode(0x212A)

const malformedSchemes = [
  '%2f%2fevil.example:/pwn',
  '%u002f%u002fevil.example:/pwn',
  '%0d%0aSet-Cookie:%20sid=attacker:/p',
  'foo%3Abar:value',
  'foo%2Fbar:value',
  '1http://example.com/',
  'foo_bar:value',
  'éxample:value',
  KELVIN_SIGN + 'ttp://example.com/',
  'ſcheme:value'
]

test('parse validates the decoded scheme against RFC 3986', (t) => {
  const validSchemes = [
    ['a:value', 'a'],
    ['HTTP://example.com/', 'http'],
    ['a1+.-:value', 'a1+.-'],
    ['%4Aavascript:alert(1)', 'javascript'],
    ['foo%2Bbar:value', 'foo+bar'],
    ['%u006Aavascript:1', 'javascript'],
    ['ht%74ps://example.com/', 'https']
  ]

  for (const [uri, scheme] of validSchemes) {
    const parsed = fastURI.parse(uri)
    t.equal(parsed.error, undefined, uri)
    t.equal(parsed.scheme, scheme, uri + ' scheme')
  }

  for (const uri of malformedSchemes) {
    const parsed = fastURI.parse(uri)
    t.equal(parsed.error, MALFORMED_SCHEME_ERROR, uri)
  }
  t.end()
})

test('decoded schemes select their scheme handlers', (t) => {
  t.equal(
    fastURI.normalize('ht%74ps://example.com:443'),
    'https://example.com/',
    'HTTP normalization runs after decoding the scheme'
  )

  // 3.x has no mailto scheme handler (added in v4); use the ws handler to
  // verify that a percent-encoded scheme still selects its scheme handler
  const ws = fastURI.parse('we%62socket://example.com/')
  t.equal(ws.scheme, 'websocket', 'ws parsing runs after decoding the scheme')
  t.end()
})

test('normalize preserves schemes that decode to invalid identifiers', (t) => {
  for (const uri of malformedSchemes) {
    t.equal(fastURI.normalize(uri), uri, uri)
  }
  t.end()
})

test('scheme normalization cannot introduce authority or control delimiters', (t) => {
  const authority = '%2f%2fevil.example:/pwn'
  const crlf = '%0d%0aSet-Cookie:%20sid=attacker:/p'

  t.equal(fastURI.parse(authority).host, undefined, 'original input has no authority')
  t.equal(fastURI.normalize(authority), authority, 'normalization does not create an authority')
  t.equal(fastURI.normalize(crlf), crlf, 'normalization does not emit raw CRLF')
  t.equal(fastURI.normalize(crlf).includes('\r\n'), false, 'normalized output contains no raw CRLF')
  t.end()
})

test('equal returns false for malformed decoded schemes', (t) => {
  for (const uri of malformedSchemes) {
    t.equal(fastURI.equal(uri, uri, {}), false, uri)
  }
  t.end()
})

test('resolve rejects malformed decoded schemes in either input', (t) => {
  t.throws(
    () => fastURI.resolve('%2f%2fevil.example:/base', 'child'),
    /URI scheme is malformed\./,
    'malformed base'
  )
  t.throws(
    () => fastURI.resolve('https://allowed.example/app/', '%2f%2fevil.example:/pwn'),
    /URI scheme is malformed\./,
    'malformed relative reference'
  )
  t.end()
})

test('serialize validates decoded component schemes', (t) => {
  t.equal(
    fastURI.serialize({ scheme: 'foo%2Bbar', path: 'value' }),
    'foo+bar:value',
    'valid decoded scheme is serialized'
  )
  t.throws(
    () => fastURI.serialize({ scheme: '//evil.example', path: '/pwn' }),
    /URI scheme is malformed\./,
    'raw invalid scheme'
  )
  t.throws(
    () => fastURI.serialize({ scheme: '%2f%2fevil.example', path: '/pwn' }),
    /URI scheme is malformed\./,
    'encoded invalid scheme'
  )
  t.equal(
    fastURI.equal(
      { scheme: '%2f%2fevil.example', path: '/pwn' },
      { scheme: '%2f%2fevil.example', path: '/pwn' },
      {}
    ),
    false,
    'equality fails closed for malformed component objects'
  )
  t.end()
})

// The exploit the advisory describes: an input that carries no authority is
// normalized into a protocol-relative reference whose host is attacker
// controlled, so a host allowlist or a "no authority means same origin" check
// made before normalization no longer describes the resulting URI.
test('an encoded scheme can not smuggle an authority into the output', (t) => {
  const vectors = [
    '%2f%2fevil.example:/pwn',
    // unescape() also decodes the non-standard %uXXXX form
    '%u002f%u002fevil.example:/pwn'
  ]

  for (const uri of vectors) {
    const parsed = fastURI.parse(uri)
    t.equal(parsed.error, MALFORMED_SCHEME_ERROR, uri + ' is reported malformed')
    t.equal(parsed.scheme, uri.split(':')[0], uri + ' keeps the scheme undecoded')
    t.equal(parsed.host, undefined, uri + ' parses without an authority')

    const normalized = fastURI.normalize(uri)
    t.equal(normalized, uri, uri + ' is handed back unchanged')
    t.equal(normalized.indexOf('//evil.example'), -1, uri + ' gains no "//" authority')
    t.equal(fastURI.parse(normalized).host, undefined, uri + ' does not reparse with a host')

    t.equal(fastURI.equal(uri, uri, {}), false, uri + ' is not comparable')
    t.throws(
      () => fastURI.resolve(uri, 'child'),
      /URI scheme is malformed\./,
      uri + ' can not be used as a resolution base'
    )
    t.throws(
      () => fastURI.resolve('https://allowed.example/app/', uri),
      /URI scheme is malformed\./,
      uri + ' can not be resolved against an allowed base'
    )
  }
  t.end()
})

// The header-injection half of the advisory: a normalized URI placed in a
// response header must never carry raw CR/LF decoded out of the scheme.
test('an encoded scheme can not smuggle CRLF into the output', (t) => {
  const uri = '%0d%0aSet-Cookie:%20sid=attacker:/p'
  const parsed = fastURI.parse(uri)

  t.equal(parsed.error, MALFORMED_SCHEME_ERROR, 'reported malformed')
  t.equal(parsed.scheme.indexOf('\r'), -1, 'parsed scheme holds no raw CR')
  t.equal(parsed.scheme.indexOf('\n'), -1, 'parsed scheme holds no raw LF')

  const normalized = fastURI.normalize(uri)
  t.equal(normalized, uri, 'handed back unchanged')
  t.equal(normalized.indexOf('\r'), -1, 'normalized output holds no raw CR')
  t.equal(normalized.indexOf('\n'), -1, 'normalized output holds no raw LF')

  t.throws(
    () => fastURI.serialize({ scheme: '%0d%0aSet-Cookie', path: '/p' }),
    /URI scheme is malformed\./,
    'serializing the component form fails closed'
  )
  t.end()
})

test('every malformed scheme vector fails closed through the whole API', (t) => {
  for (const uri of malformedSchemes) {
    const scheme = uri.split(':')[0]

    t.throws(
      () => fastURI.serialize({ scheme, path: '/pwn' }),
      /URI scheme is malformed\./,
      'serialize rejects ' + scheme
    )
    t.throws(
      () => fastURI.normalize({ scheme, path: '/pwn' }),
      /URI scheme is malformed\./,
      'normalize rejects the component form of ' + scheme
    )
    t.throws(
      () => fastURI.resolve(uri, 'child'),
      /URI scheme is malformed\./,
      'resolve rejects ' + uri + ' as base'
    )
    t.throws(
      () => fastURI.resolve('https://allowed.example/app/', uri),
      /URI scheme is malformed\./,
      'resolve rejects ' + uri + ' as relative reference'
    )
    t.equal(
      fastURI.equal({ scheme, path: '/pwn' }, { scheme, path: '/pwn' }, {}),
      false,
      'equal fails closed for the component form of ' + scheme
    )
  }
  t.end()
})

// Pre-fix the scheme handler was looked up with the still-encoded scheme, so
// scheme-specific parsing was skipped for any percent-encoded scheme.
test('a percent-encoded scheme still selects its handler', (t) => {
  const ws = fastURI.parse('w%73://example.com/chat')
  t.equal(ws.error, undefined, 'no error')
  t.equal(ws.scheme, 'ws', 'scheme is decoded')
  t.equal(ws.secure, false, 'ws handler set the secure flag')
  t.equal(ws.resourceName, '/chat', 'ws handler produced the resource name')
  t.equal(ws.path, undefined, 'ws handler consumed the path')

  const wss = fastURI.parse('ws%73://example.com/chat')
  t.equal(wss.scheme, 'wss', 'scheme is decoded')
  t.equal(wss.secure, true, 'wss handler set the secure flag')
  t.end()
})

// A scheme that survives validation contains no "%", so serializing an
// already-parsed component can not decode a second time. A doubly-encoded
// scheme therefore fails closed instead of peeling one layer per pass.
test('valid decoded schemes round-trip without a second decode', (t) => {
  t.equal(fastURI.normalize('foo%2Bbar:value'), 'foo+bar:value', 'foo%2Bbar')
  t.equal(fastURI.normalize('ht%74ps://example.com/a'), 'https://example.com/a', 'ht%74ps')
  t.equal(fastURI.serialize(fastURI.parse('foo%2Bbar:value')), 'foo+bar:value', 'parse then serialize')
  t.equal(fastURI.equal('ht%74ps://example.com/a', 'https://example.com/a'), true, 'encoded and plain compare equal')
  t.throws(
    () => fastURI.serialize({ scheme: 'foo%252Bbar', path: 'value' }),
    /URI scheme is malformed\./,
    'a doubly-encoded scheme is decoded once and then rejected'
  )
  t.equal(fastURI.normalize('%252f%252fevil.example:/pwn'), '%252f%252fevil.example:/pwn', 'doubly-encoded authority is not peeled')
  t.end()
})
