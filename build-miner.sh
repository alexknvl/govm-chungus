#!/bin/bash

go clean -r
rm ./mining
go build -ldflags "-s -w" -trimpath && upx --brute mining