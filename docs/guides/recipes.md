# Writing a recipe

A recipe says how to build the target. Without one, the tool tries to
detect the build from the repository layout, which works for many
projects but not for all of them.

## The file

`.verdis/recipe.yml` in the root of the repository.

```yaml
language: c
build:
  system: cmake
  flags: [asan, ubsan]
  steps:
    - cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
    - cmake --build build -j
  env:
    CFLAGS: -fsanitize=address,undefined
run:
  workdir: /work
  default_timeout: 30s
  repeat: 3
```

## The fields

| Field | Meaning |
| --- | --- |
| `language` | `c`, `cpp`, `python`, `node`, `go`, `rust`, `java`, `docker` or `unknown`. |
| `build.system` | `cmake`, `make`, `autotools`, `pip`, `npm`, `go`, `cargo`, `gradle` or `docker`. |
| `build.flags` | the sanitizers to enable: `asan`, `ubsan`, `tsan`, `msan`, `race`. |
| `build.steps` | the commands to run, in order. |
| `build.env` | environment variables for the build. |
| `build.image` | a pinned image, by digest. |
| `run.workdir` | the workdir inside the sandbox. |
| `run.default_timeout` | how long a single run may take. |
| `run.repeat` | how many times the PoC is run, to detect flakiness. |

## Instrumented builds

Use them. A crash that is only visible under a sanitizer is the difference
between `REPRODUCED` and `NOT_REPRODUCED`.

- **C and C++** — `flags: [asan, ubsan]`. The detector adds
  `-fsanitize=address,undefined -fno-omit-frame-pointer` for you.
- **Go** — `flags: [race]`. The detector adds `go build -race ./...`.
- **Everything else** — assertion-enabled builds.

## What the tool detects on its own

| The repository has | The tool builds with |
| --- | --- |
| `Dockerfile` | Docker mode |
| `CMakeLists.txt` | CMake with ASan and UBSan |
| `Makefile` | make with ASan and UBSan |
| `configure.ac` or `configure` | autotools with ASan and UBSan |
| `go.mod` | `go build -race ./...` |
| `pyproject.toml` or `setup.py` | `pip install .` |
| `package.json` | `npm install --ignore-scripts` |
| `Cargo.toml` | `cargo build --release` |
| `pom.xml` or `build.gradle` | `gradle build -x test` |

Detection is a starting point. When it is wrong, write the recipe.

## The two phases

The build stage may reach an allowlisted mirror, because dependencies have
to come from somewhere. The run stage never does. If your build needs
something unusual, vendor it and add a recipe step that uses the vendored
copy.

## Checking a recipe

```bash
verdis recipe init
verdis recipe validate
```

`validate` checks that the file parses and reports what it found. It does
not build anything; the real test is a triage run.
