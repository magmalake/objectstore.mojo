# Changelog

## Unreleased

## 0.4.1 - 2026-11-03

- The shim is found without `CONDA_PREFIX`: after `$CONDA_PREFIX/lib`,
  objectstore looks next to the executable, in its `../lib`, and on the
  binary's rpath (the environment `mojo build` ran in), so a binary built
  with `pixi run mojo build` runs from a plain shell. The search lives in
  `src/objectstore/_dlopen.mojo`, shared with the other magmalake tins that
  load a library.
- The shim is opened once per process and never closed, as in zstd, instead
  of a `dlopen`/`dlclose` per call. A shim that can't be found is an Error
  naming the library and every place searched and saying to set
  `CONDA_PREFIX`.
- The fallback to `build/libobjectstoremojo.so` relative to the working
  directory is gone: it named a file only objectstore.mojo's own checkout
  had, and loading a library from the working directory isn't safe.
