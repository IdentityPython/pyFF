#!/bin/bash

base=$1
target=$2
dir=`mktemp -d`

if [ "x${MIRROR_MDQ_POST}" = "x" ]; then
   export MIRROR_MDQ_POST="/etc/mirror-mdq/post.d"
fi

function cleanup() {
   rm -rf $dir
}

trap cleanup EXIT

mkdir -p $target && (
 cd $dir
 WGET_ARGS="--mirror --no-host-directories -q"
 idx_obj=".well-known/webfinger?rel=urn:oasis:names:tc:SAML:2.0:metadata"
 wget $WGET_ARGS "$base/$idx_obj" && jq -r '.links[].href' < "$idx_obj" | wget $WGET_ARGS -i -
 if [ -d "${MIRROR_MDQ_POST}" ]; then
    env SOURCE=$1 TARGET=$target IDX_OBJ=$idx_obj run-parts --regex '^[0-9]+-' -- ${MIRROR_MDQ_POST}
 fi
)

rsync -az $RSYNC_ARGS --delete $dir/ $target/
