#!/bin/sh
# create a signed XML file per EntityDescriptor for ADFS

# Step 1. Split aggregate and create an XML and a pipeline file per EntityDescriptor
/usr/bin/mdsplit.py \
    -c /etc/pki/pyff/metadata_signing-crt.pem \
    -k /etc/pki/pyff/metadata_signing-key.pem \
    -l /var/log/pyffsplit.log \
    -L DEBUG \
    /var/md_feed/metadata.xml \
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

