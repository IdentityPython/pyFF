#!/bin/sh
# create a signed XML file per EntityDescriptor for ADFS

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
/usr/bin/mdsplit.py \
    -c $MDSIGN_CERT \
    -k $MDSIGN_KEY \
    -l /var/log/pyffsplit.log \
    -L DEBUG \
    $MD_AGGREGATE \
    /var/md_feed/split/ \
    /var/md_source/split/

# Step 2. Execute pyff to sign each EntityDescriptor
cd /var/md_source/split/
for fn in *.fd; do
    echo "running pyff for $fn"
    /usr/bin/pyff --loglevel=$LOGLEVEL $fn
done

# make metadata files availabe to nginx container:
chmod 644 /var/md_feed/split/*.xml 2> /dev/null

