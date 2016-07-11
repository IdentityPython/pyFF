#!/bin/sh
# create a signed XML file per EntityDescriptor for ADFS

MDSPLITUNSIGNED='/var/md_source/split/'
MDSPLITSIGNED='/var/md_feed/split/'
LOGFILE='/var/log/pyffsplit.log'
# MDSIGN_CERT, MDSIGN_KEY and MDAGGREGATE must be passed via env
if [ ! -e $MDSIGN_CERT ]; then
    echo "MDSIGN_CERT must be set and point to an existing file" && exit 1
fi
if [ ! -e $MDSIGN_KEY ]; then
    echo "MDSIGN_KEY must be set and point to an existing file" && exit 1
fi
if [ ! -e $MD_AGGREGATE ]; then
    echo "MD_AGGREGATE must be set and point to an existing file" && exit 1
fi

# Step 1. Split aggregate and create an XML and a pipeline file per EntityDescriptor
[ "$LOGLEVEL" == "DEBUG" ] && echo "processing "
/usr/bin/mdsplit.py \
    -c $CERTFILE -k $KEYFILE \
    -l $LOGFILE -L DEBUG \
    $MD_AGGREGATE $MDSPLITUNSIGNED $MDSPLITSIGNED

# Step 2. Execute pyff to sign each EntityDescriptor
cd $MDSPLITUNSIGNED
for fn in *.fd; do
    echo "running pyff for $fn"
    /usr/bin/pyff --loglevel=$LOGLEVEL $fn
done

# make metadata files availabe to nginx container:
chmod 644 /var/md_feed/split/*.xml 2> /dev/null

