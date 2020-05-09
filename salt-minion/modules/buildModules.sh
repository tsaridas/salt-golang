#!/bin/bash
for mod in $(ls *.go | sed 's/.go//')
do
	go build -ldflags="-s -w" -buildmode=plugin -o ./"$mod".so ./"$mod".go
done
