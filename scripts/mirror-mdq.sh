#!/bin/bash

usage() {
   echo
   echo "Usage:"
   echo 
   echo "`basename $0` [-S|-D|-A] [-h] <base MDX URL> <target rsync enpoint>"
   echo
   echo "    -S:  only SAML metadata"
   echo "    -D:  only discojson metadata"
   echo "    -A:  all metadata"
   echo "    -h:  show this message"
   echo
   echo "Mirror an MDQ service by querying the .well-known/webfinger"
   echo "endpoint and fetching all links of the specified type. This"
   echo "tool uses jq to parse JSON and wget to fetch URLs."
   echo
   echo "Data is fetched to a local dir and then rsync:ed with --delete"
   echo "to the target which can be a remote (ssh) location. Optionally"
   echo "run-parts a set of post-processing scripts in the temporary"
   echo "directory before rsync."
   echo
   exit 1
}

rel=""

while getopts SAD c; do
   case $c in
      S) rel="urn:oasis:names:tc:SAML:2.0:metadata" ;;
      A) rel="" ;;
      D) rel="disco-json" ;;
      h) usage ;;
   esac
done

base=$1
target=$2

if [ "x$base" = "x" -o "x$target" = "x" ]; then
   usage
fi

dir=`env TMPDIR=/var/tmp mktemp -d` # to be able to use user extended attributes in post.d

relarg=""
if [ "x$rel" != "x" ]; then
   relarg = "?rel=$rel"
fi

if [ "x${MIRROR_MDQ_POST}" = "x" ]; then
   export MIRROR_MDQ_POST="/etc/mirror-mdq/post.d"
fi

function cleanup() {
   rm -rf $dir
}

function err() {
   echo "*** ERROR $1"
   exit $2
}

trap cleanup EXIT

echo $target | grep -qv '@' && mkdir -p $target 

(
 cd $dir
 WGET_ARGS="--mirror --no-host-directories -q --connect-timeout=10"
 idx_obj=".well-known/webfinger$relarg"
 if wget $WGET_ARGS "$base/$idx_obj"; then 
    jq -r '.links[].href' < "$idx_obj" | xargs -P 10 -r -n 1 wget $WGET_ARGS
    ret=$?
 else
    err "Failed to fetch metadata index $idx_obj" $?
 fi
 if [ $ret -ne 0 ]; then
    err "Failed to mirror metadata from $base" $ret
 fi
 if [ -d "${MIRROR_MDQ_POST}" ]; then
    env SOURCE=$1 TARGET=$target IDX_OBJ=$idx_obj run-parts --regex '^[0-9]+-' -- ${MIRROR_MDQ_POST}
    ret=$?
    if [ $ret -ne 0 ]; then
       err "Failed post-processing metadata from $base" $ret
    fi
 fi
)
ret=$?
if [ $ret -ne 0 ]; then
   err "Mirror of metadata from $base failed - skipping final rsync" $ret
fi
rsync -az $RSYNC_ARGS --delete $dir/ $target/
