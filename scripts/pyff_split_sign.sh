#!/bin/sh
# create a signed XML file per EntityDescriptor for ADFS

# MDSIGN_CERT, MDSIGN_KEY and MDAGGREGATE must be passed via env
[ $MDSIGN_CERT ] || echo "MDSIGN_CERT must be set and point to an existing file" && exit 1
[ $MDSIGN_KEY ] || echo "MDSIGN_KEY must be set and point to an existing file" && exit 1
[ $MD_AGGREGATE ]|| echo "MD_AGGREGATE must be set and point to an existing file" && exit 1
# Setting defaults
[ $MDSPLIT_UNSIGNED ] || MDSPLIT_UNSIGNED='/var/md_source/split/'
[ $MDSPLIT_SIGNED ] || MDSPLIT_SIGNED='/var/md_feed/split/'
[ $LOGFILE ] || LOGFILE='/var/log/pyffsplit.log'

# Step 1. Split aggregate and create an XML and a pipeline file per EntityDescriptor
[ "$LOGLEVEL" == "DEBUG" ] && echo "processing "
/usr/bin/pyff_mdsplit.py \
    -c $MDSIGN_CERT -k $MDSIGN_KEY \
    -l $LOGFILE -L DEBUG \
    $MD_AGGREGATE $MDSPLIT_UNSIGNED $MDSPLIT_SIGNED

# Step 2. Execute pyff to sign each EntityDescriptor
cd $MDSPLIT_UNSIGNED
for fn in *.fd; do
    echo "running pyff for $fn"
    /usr/bin/pyff --loglevel=$LOGLEVEL $fn
done

# make metadata files availabe to nginx container:
chmod 644 /var/md_feed/split/*.xml 2> /dev/null

