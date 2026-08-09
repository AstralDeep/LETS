# LETS-CJ/1 canonical signed JSON

Every LETS signature and content digest is over UTF-8 bytes produced by the deliberately small
`LETS-CJ/1` profile. It is not RFC 8785/JCS: LETS uses lossless signed 64-bit integers for resource
vectors, epochs, sequence numbers, and nanosecond timestamps, while JCS-compatible consumers may
parse numbers through an IEEE-754 representation.

The profile is:

- object keys are strings, sorted by Unicode scalar value, with no Unicode normalization;
- arrays preserve order; protocol sets are converted to explicitly sorted arrays before signing;
- values are JSON null, booleans, strings, signed 64-bit integers, arrays, and objects;
- floats, NaN, infinities, non-string keys, duplicate JSON keys, and lone Unicode surrogates are
  rejected;
- output has no insignificant whitespace, uses UTF-8, escapes controls as JSON requires, and uses
  lowercase JSON literals;
- binary values internal to an implementation are encoded as unpadded base64url strings; wire
  decoders reject padding, ignored characters, and every non-canonical spelling.

Implementations must parse integers losslessly before checking the signed 64-bit bound. A JSON
parser that silently rounds large values, accepts non-finite numbers, or keeps one of two duplicate
keys is not a conforming LETS parser.

## Conformance vectors

```text
input:  {"b":2,"a":1}
bytes:  {"a":1,"b":2}

input:  {"control":"<NUL>\n\t","max":9223372036854775807,"min":-9223372036854775808}
bytes:  {"control":"\u0000\n\t","max":9223372036854775807,"min":-9223372036854775808}
```

The executable vectors, including the Unicode scalar-order and non-normalization cases, live in
`tests/security/test_canonical_wire.py`.
