# Changelog

## 0.4.2 - 2026-11-04

The shim is objectstore-shim 0.2.1, so a project that mixes packages pinning
0.4.1 and 0.4.2 sees two versions of it, not two records of one.

- Multipart uploads complete on real AWS S3. `CompleteMultipartUpload` was
  answered `403 SignatureDoesNotMatch` every time, after create and every
  part had succeeded. The shim sends bodies as `CURLOPT_POSTFIELDS`, and curl
  then adds `Content-Type: application/x-www-form-urlencoded` to any request
  that doesn't set one. S3 parses a form-encoded POST body as query
  parameters and puts them in the canonical request it checks the signature
  against, so the XML part list became a query parameter the client never
  signed. MinIO doesn't do this, which is why CI passed. Two fixes: the shim
  no longer sends a Content-Type the caller didn't give (POST, PUT, PATCH,
  with or without a body), and `complete_multipart_upload` sends
  `Content-Type: application/xml` itself, signed, so it also works with an
  older installed shim.
- Objects written without a content type no longer get
  `application/x-www-form-urlencoded` as their stored Content-Type, which the
  same curl default did to every `put_object` and `CreateMultipartUpload`
  (and to Azure/GCS PUTs through `HttpOutputFile`). S3 now stores its own
  default, `binary/octet-stream`.
- Tests: the local HTTP test server has a `/headers/` route that echoes every
  request header as received, and new tests assert that body requests carry
  no unrequested Content-Type and that every header an S3 write puts on the
  wire was signed (or is one SigV4 lets travel unsigned).

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
