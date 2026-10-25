# Heap buffer overflow in parse_header

**Version**: 2.3.1
**Component**: src/hdr.c:parse_header
**Class**: CWE-122

Parsing a crafted header causes a heap buffer overflow in `parse_header()`.

## Steps to reproduce

```
./build/parse_demo poc.bin
```

## Expected behaviour

AddressSanitizer reports a `heap-buffer-overflow` in `parse_header`.

## Impact

Memory corruption leading to a crash.
