#!/usr/bin/env bash
set -euo pipefail
umask 077
package=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
host=com.cpqa.crypto_agent
case "$(uname -s)" in
    Darwin)
        root="$HOME/Library/Application Support/CPQA/Crypto Agent"
        chrome="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
        edge="$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts"
        ;;
    Linux)
        root="${XDG_DATA_HOME:-$HOME/.local/share}/cpqa/crypto-agent/runtime"
        chrome="${XDG_CONFIG_HOME:-$HOME/.config}/google-chrome/NativeMessagingHosts"
        edge="${XDG_CONFIG_HOME:-$HOME/.config}/microsoft-edge/NativeMessagingHosts"
        ;;
    *) printf '%s\n' 'Unsupported platform.' >&2; exit 1 ;;
esac
mkdir -p -- "$root" "$chrome" "$edge"
destination=$(mktemp -d "$root/install.XXXXXXXX")
cp -R -- "$package/runtime/." "$destination/"
chmod 700 -- "$destination/cpqa-crypto-agent"
path="$destination/cpqa-crypto-agent"
if [[ "$path" == *[[:cntrl:]]* ]]; then
    printf '%s\n' 'The install path contains unsupported characters.' >&2
    exit 1
fi
path=${path//\\/\\\\}
path=${path//\"/\\\"}
while IFS= read -r line; do
    if [[ "$line" == *'__CPQA_EXECUTABLE__'* ]]; then
        printf '%s%s%s\n' "${line%%__CPQA_EXECUTABLE__*}" "$path" "${line#*__CPQA_EXECUTABLE__}"
    else
        printf '%s\n' "$line"
    fi
done < "$package/native-host.json" > "$destination/native-host.json"
for directory in "$chrome" "$edge"; do
    temporary=$(mktemp "$directory/.$host.XXXXXXXX")
    cp -- "$destination/native-host.json" "$temporary"
    mv -f -- "$temporary" "$directory/$host.json"
done
printf '%s\n' 'Crypto Agent installed. Return to CPQA and check again.'
