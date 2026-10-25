# Local denial of service in the report generator

**Version**: 2.3.1
**Component**: src/report.c:generate_report
**Class**: CWE-400

Generating a report from a very large input takes unbounded time and
memory.

## Steps to reproduce

```
./build/report_demo --rows 100000000 big.csv
```

## Impact

Denial of service from unbounded local CLI input.
