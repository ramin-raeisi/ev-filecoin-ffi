# Filecoin Proofs FFI

> C and CGO bindings for =nil; Foundation's Filecoin's C++ Prover

## go get

`go get` needs some additional steps in order to work as expected.

Get the source, add this repo as a submodule to your repo, build it and point to it:

```shell
$ go get github.com/nilfoundation/filecoin-ffi
$ git submodule add https://github.com/nilfoundation/filecoin-ffi.git extern/filecoin-ffi
$ make -C extern/filecoin-ffi
$ go mod edit -replace=github.com/nilfoundation/filecoin-ffi=./extern/filecoin-ffi
```

## Updating CGO Bindings

The CGO bindings are generated using [c-for-go](https://github.com/xlab/c-for-go)
and committed to Git. To generate bindings yourself, install the c-for-go
binary, ensure that it's on your path, and then run `make cgo-gen`. CI builds
will fail if generated CGO diverges from what's checked into Git.

## License

MIT or Apache 2.0
