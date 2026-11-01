#!/bin/sh
set -eu
# A named volume survives image upgrades. Refresh executable artifacts on every
# start so an existing volume cannot hide the plugin bundled with the new image.
# Never touch Vault storage, configuration, certificates or keys here.
for artifact in /opt/cpqa/crypto/plugin/vault-plugin-abe /opt/cpqa/crypto/lib/libhybrid-pq-cp-abe.so; do
    name=$(basename "$artifact")
    cp "$artifact" "/vault/plugins/.$name.new"
    chmod 755 "/vault/plugins/.$name.new"
    mv -f "/vault/plugins/.$name.new" "/vault/plugins/$name"
done
cp /opt/cpqa/crypto/source.env /vault/plugins/crypto-source.env
exec /usr/bin/vault "$@"
