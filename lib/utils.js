'use strict'

/** @type {(value: string) => boolean} */
const isUUID = RegExp.prototype.test.bind(/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/iu)

/** @type {(value: string) => boolean} */
const isIPv4 = RegExp.prototype.test.bind(/^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)$/u)

/** @type {(value: string) => boolean} */
const isHexPair = RegExp.prototype.test.bind(/^[\da-f]{2}$/iu)

/** @type {(value: string) => boolean} */
const isUnreserved = RegExp.prototype.test.bind(/^[\da-z\-._~]$/iu)

/** @type {(value: string) => boolean} */
const isPathCharacter = RegExp.prototype.test.bind(/^[\da-z\-._~!$&'()*+,;=:@/]$/iu)

/**
 * @param {Array<string>} input
 * @returns {string}
 */
function stringArrayToHexStripped (input) {
  let acc = ''
  let code = 0
  let i = 0

  for (i = 0; i < input.length; i++) {
    code = input[i].charCodeAt(0)
    if (code === 48) {
      continue
    }
    if (!((code >= 48 && code <= 57) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102))) {
      return ''
    }
    acc += input[i]
    break
  }

  for (i += 1; i < input.length; i++) {
    code = input[i].charCodeAt(0)
    if (!((code >= 48 && code <= 57) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102))) {
      return ''
    }
    acc += input[i]
  }
  return acc
}

/** @type {(value: string) => boolean} */
const isHextet = RegExp.prototype.test.bind(/^[\dA-Fa-f]{1,4}$/)

/** @type {(value: string) => boolean} */
const isIPvFuture = RegExp.prototype.test.bind(/^[vV][\dA-Fa-f]+\.[A-Za-z\d\-._~!$&'()*+,;=:]+$/)

/** @type {(value: string) => boolean} */
const isZoneCharacter = RegExp.prototype.test.bind(/^[A-Za-z\d\-._~]$/)

/**
 * @param {string} value
 * @returns {boolean}
 */
const nonSimpleDomain = RegExp.prototype.test.bind(/[^!"$&'()*+,\-.;=_`a-z{}~]/u)

/**
 * @param {string} zone
 * @returns {boolean}
 */
function isZoneIdentifier (zone) {
  if (zone.length === 0) return false

  for (let i = 0; i < zone.length; i++) {
    if (isZoneCharacter(zone[i])) continue
    if (zone[i] === '%' && i + 2 < zone.length && isHexPair(zone.slice(i + 1, i + 3))) {
      i += 2
      continue
    }
    return false
  }

  return true
}

/**
 * Compresses the longest run of zero hextets to "::" per RFC 5952. A run of a
 * single zero hextet is left uncompressed. On ties the leftmost run wins.
 *
 * @param {string[]} hextets
 * @returns {string}
 */
function compressIPv6ZeroRun (hextets) {
  let bestStart = -1
  let bestLength = 0
  let runStart = -1
  let runLength = 0
  for (let i = 0; i < hextets.length; i++) {
    if (hextets[i] === '0') {
      if (runStart === -1) runStart = i
      runLength++
      if (runLength > bestLength) {
        bestLength = runLength
        bestStart = runStart
      }
    } else {
      runStart = -1
      runLength = 0
    }
  }

  if (bestLength < 2) return hextets.join(':')

  const head = hextets.slice(0, bestStart).join(':')
  const tail = hextets.slice(bestStart + bestLength).join(':')
  return head + '::' + tail
}

/**
 * Validates an IPv6 address against the alternatives in RFC 3986 section
 * 3.2.2 and returns the same address with leading hextet zeroes removed.
 * An embedded IPv4 address counts as two hextets and is only valid at the end.
 *
 * @param {string} input
 * @returns {string|undefined}
 */
function normalizeIPv6Address (input) {
  const compression = input.indexOf('::')
  if (compression !== -1 && input.indexOf('::', compression + 1) !== -1) return undefined

  const left = compression === -1 ? input.split(':') : input.slice(0, compression).split(':')
  const right = compression === -1 ? [] : input.slice(compression + 2).split(':')
  if (compression !== -1) {
    if (left.length === 1 && left[0] === '') left.length = 0
    if (right.length === 1 && right[0] === '') right.length = 0
  }

  const parts = left.concat(right)
  let hextetCount = 0
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]
    if (part === '') return undefined

    if (part.indexOf('.') !== -1) {
      if (i !== parts.length - 1 || (compression !== -1 && right.length === 0) || !isIPv4(part)) return undefined
      hextetCount += 2
      continue
    }

    if (!isHextet(part)) return undefined
    parts[i] = parseInt(part, 16).toString(16)
    hextetCount++
  }

  if (compression === -1) {
    if (hextetCount !== 8) return undefined
    return compressIPv6ZeroRun(parts)
  }
  if (hextetCount >= 8) return undefined

  // expand "::" then re-compress the longest run for a canonical result
  const expanded = parts.slice(0, left.length)
  for (let i = hextetCount; i < 8; i++) expanded.push('0')
  for (let i = left.length; i < parts.length; i++) expanded.push(parts[i])
  return compressIPv6ZeroRun(expanded)
}

/**
 * @typedef {Object} NormalizeIPv6Result
 * @property {string} host - The normalized host.
 * @property {string} [escapedHost] - The escaped host.
 * @property {boolean} isIPV6 - Indicates if the host is an IPv6 address.
 * @property {boolean} [isIPVFuture] - Indicates if the host is an IPvFuture literal.
 * @property {boolean} [error] - Indicates if a bracketed IP literal is malformed.
 */

/**
 * Validates and normalizes a bracketed IP literal. Raw zone separators remain
 * accepted for backwards compatibility, while encoded separators and zone
 * contents follow RFC 6874. A bracketed literal that is not a valid IPv6 or
 * IPvFuture address is reported as an error instead of being rewritten.
 *
 * @param {string} host
 * @returns {NormalizeIPv6Result}
 */
function normalizeIPv6 (host) {
  const bracketed = host[0] === '[' && host[host.length - 1] === ']'
  const hasBracket = host[0] === '[' || host[host.length - 1] === ']'
  if (hasBracket && !bracketed) return { host, isIPV6: false, error: true }

  let input = bracketed ? host.slice(1, -1) : host
  if (bracketed && isIPvFuture(input)) {
    input = input.toLowerCase()
    return { host: `[${input}]`, escapedHost: input, isIPV6: false, isIPVFuture: true }
  }

  if (findToken(input, ':') < 2) {
    return { host, isIPV6: false, error: bracketed }
  }

  let zoneIdentifier = ''
  const zoneSeparator = input.indexOf('%')
  if (zoneSeparator !== -1) {
    const separatorLength = input.slice(zoneSeparator, zoneSeparator + 3).toLowerCase() === '%25' ? 3 : 1
    zoneIdentifier = input.slice(zoneSeparator + separatorLength)
    if (!isZoneIdentifier(zoneIdentifier)) return { host, isIPV6: false, error: true }
    input = input.slice(0, zoneSeparator)
  }

  const address = normalizeIPv6Address(input)
  if (address === undefined) return { host, isIPV6: false, error: true }

  return {
    host: address + (zoneIdentifier ? '%' + zoneIdentifier : ''),
    escapedHost: address + (zoneIdentifier ? '%25' + zoneIdentifier : ''),
    isIPV6: true
  }
}

/**
 * @param {string} str
 * @param {string} token
 * @returns {number}
 */
function findToken (str, token) {
  let ind = 0
  for (let i = 0; i < str.length; i++) {
    if (str[i] === token) ind++
  }
  return ind
}

/**
 * @param {string} path
 * @returns {string}
 *
 * @see https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.4
 */
function removeDotSegments (path) {
  let input = path
  const output = []
  let nextSlash = -1
  let len = 0

  // eslint-disable-next-line no-cond-assign
  while (len = input.length) {
    if (len === 1) {
      if (input === '.') {
        break
      } else if (input === '/') {
        output.push('/')
        break
      } else {
        output.push(input)
        break
      }
    } else if (len === 2) {
      if (input[0] === '.') {
        if (input[1] === '.') {
          break
        } else if (input[1] === '/') {
          input = input.slice(2)
          continue
        }
      } else if (input[0] === '/') {
        if (input[1] === '.' || input[1] === '/') {
          output.push('/')
          break
        }
      }
    } else if (len === 3) {
      if (input === '/..') {
        if (output.length !== 0) {
          output.pop()
        }
        output.push('/')
        break
      }
    }
    if (input[0] === '.') {
      if (input[1] === '.') {
        if (input[2] === '/') {
          input = input.slice(3)
          continue
        }
      } else if (input[1] === '/') {
        input = input.slice(2)
        continue
      }
    } else if (input[0] === '/') {
      if (input[1] === '.') {
        if (input[2] === '/') {
          input = input.slice(2)
          continue
        } else if (input[2] === '.') {
          if (input[3] === '/') {
            input = input.slice(3)
            if (output.length !== 0) {
              output.pop()
            }
            continue
          }
        }
      }
    }

    // Rule 2E: Move normal path segment to output
    if ((nextSlash = input.indexOf('/', 1)) === -1) {
      output.push(input)
      break
    } else {
      output.push(input.slice(0, nextSlash))
      input = input.slice(nextSlash)
    }
  }

  return output.join('')
}

/**
 * Re-escape RFC 3986 gen-delims that must not appear literally in the host.
 * After the URI regex parses, these characters cannot be literal in the host
 * field, so any that appear after decoding came from percent-encoding and
 * must be restored to prevent authority structure changes.
 *
 * @param {string} host
 * @param {boolean} isIP - true for IPv4/IPv6 hosts (skip colon re-escaping)
 * @returns {string}
 */
const HOST_DELIMS = { '@': '%40', '/': '%2F', '?': '%3F', '#': '%23', ':': '%3A' }
const HOST_DELIM_RE = /[@/?#:]/g
const HOST_DELIM_NO_COLON_RE = /[@/?#]/g

function reescapeHostDelimiters (host, isIP) {
  const re = isIP ? HOST_DELIM_NO_COLON_RE : HOST_DELIM_RE
  re.lastIndex = 0
  return host.replace(re, (ch) => HOST_DELIMS[ch])
}

/**
 * Normalizes percent escapes and optionally decodes only unreserved ASCII bytes.
 * Reserved delimiters such as `%2F` and `%2E` stay escaped.
 *
 * @param {string} input
 * @param {boolean} [decodeUnreserved=false]
 * @returns {string}
 */
function normalizePercentEncoding (input, decodeUnreserved = false) {
  if (input.indexOf('%') === -1) {
    return input
  }

  let output = ''

  for (let i = 0; i < input.length; i++) {
    if (input[i] === '%' && i + 2 < input.length) {
      const hex = input.slice(i + 1, i + 3)
      if (isHexPair(hex)) {
        const normalizedHex = hex.toUpperCase()
        const decoded = String.fromCharCode(parseInt(normalizedHex, 16))

        if (decodeUnreserved && isUnreserved(decoded)) {
          output += decoded
        } else {
          output += '%' + normalizedHex
        }

        i += 2
        continue
      }
    }

    output += input[i]
  }

  return output
}

/**
 * Normalizes path data without turning reserved escapes into live path syntax.
 * Valid escapes are uppercased, raw unsafe characters are escaped, and only
 * unreserved bytes that are not `.` are decoded.
 *
 * @param {string} input
 * @returns {string}
 */
function normalizePathEncoding (input) {
  let output = ''

  for (let i = 0; i < input.length; i++) {
    if (input[i] === '%' && i + 2 < input.length) {
      const hex = input.slice(i + 1, i + 3)
      if (isHexPair(hex)) {
        const normalizedHex = hex.toUpperCase()
        const decoded = String.fromCharCode(parseInt(normalizedHex, 16))

        if (decoded !== '.' && isUnreserved(decoded)) {
          output += decoded
        } else {
          output += '%' + normalizedHex
        }

        i += 2
        continue
      }
    }

    if (isPathCharacter(input[i])) {
      output += input[i]
    } else {
      output += escape(input[i])
    }
  }

  return output
}

/**
 * Escapes a component while preserving existing valid percent escapes.
 *
 * @param {string} input
 * @returns {string}
 */
function escapePreservingEscapes (input) {
  let output = ''

  for (let i = 0; i < input.length; i++) {
    if (input[i] === '%' && i + 2 < input.length) {
      const hex = input.slice(i + 1, i + 3)
      if (isHexPair(hex)) {
        output += '%' + hex.toUpperCase()
        i += 2
        continue
      }
    }

    output += escape(input[i])
  }

  return output
}

/**
 * @param {import('../types/index').URIComponent} component
 * @returns {string|undefined}
 */
function recomposeAuthority (component) {
  const uriTokens = []

  if (component.userinfo !== undefined) {
    uriTokens.push(component.userinfo)
    uriTokens.push('@')
  }

  if (component.host !== undefined) {
    let host = String(component.host)
    if (!isIPv4(host)) {
      let ipV6res = normalizeIPv6(host)
      if (ipV6res.isIPV6 !== true && ipV6res.isIPVFuture !== true) {
        // Decode the host only once it is known not to be an IP literal: a zone
        // identifier may legitimately carry escapes that decoding would rewrite
        // into a different address.
        host = unescape(host)
        ipV6res = normalizeIPv6(host)
      }
      if (ipV6res.isIPV6 === true || ipV6res.isIPVFuture === true) {
        host = `[${ipV6res.escapedHost}]`
      } else {
        host = reescapeHostDelimiters(host, false)
      }
    }
    uriTokens.push(host)
  }

  if (typeof component.port === 'number' || typeof component.port === 'string') {
    uriTokens.push(':')
    uriTokens.push(String(component.port))
  }

  return uriTokens.length ? uriTokens.join('') : undefined
};

module.exports = {
  nonSimpleDomain,
  recomposeAuthority,
  reescapeHostDelimiters,
  normalizePercentEncoding,
  normalizePathEncoding,
  escapePreservingEscapes,
  removeDotSegments,
  isIPv4,
  isUUID,
  normalizeIPv6,
  stringArrayToHexStripped
}
