# Path traversal in the file reader

**Version**: 1.4.0
**Component**: main.py:main
**Class**: CWE-22

The file reader joins the name in the request to the directory it is
meant to serve, without checking that the result stays inside it. A name
that climbs out of the served directory reaches the files beside it, and
their contents are returned to whoever asked.

## Steps to reproduce

```
python3 ./main.py poc.bin
```

`poc.bin` holds the name of the file to read.

## Expected output

```
VERDIS_SECRET_9f3a
```

## Impact

A file outside the served directory is disclosed to whoever can name it.
