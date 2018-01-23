#!/bin/bash

base=$1
target=$2
dir=`mktemp -d`

function cleanup() {
   rm -rf $dir
}

trap cleanup EXIT

mkdir -p $target && (
 cd $dir
 WGET_ARGS="--mirror --no-host-directories -q"
 idx_obj=".well-known/webfinger?rel=urn:oasis:names:tc:SAML:2.0:metadata"
 wget $WGET_ARGS "$base/$idx_obj" && jq -r '.links[].href' < "$idx_obj" | wget $WGET_ARGS -i -
)

rsync -az --delete $dir/ $target/ 
