#!/bin/bash

set -e

make clean
FFI_BUILD_FROM_SOURCE=1 make
go mod tidy
