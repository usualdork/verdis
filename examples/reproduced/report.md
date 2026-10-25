# Heap buffer overflow in parse_header

**Version**: 2.3.1
**Component**: src/hdr.c:parse_header
**Class**: CWE-122

Parsing a crafted header causes a heap buffer overflow in `parse_header()`.
The header length is copied into a 16-byte allocation without being
checked, so a header longer than 16 bytes writes past the end of the
buffer.

## Steps to reproduce

```
./build/parse_demo poc.bin
```

`poc.bin` is 64 bytes of `A`.

## Expected behaviour

AddressSanitizer reports a `heap-buffer-overflow` in `parse_header`.

## Impact

Memory corruption leading to a crash; a remote attacker who controls the
header bytes may be able to go further.

## Notes

This is a synthetic example that ships with Verdis so the docs have
something real to point at. See `examples/reproduced/`.
