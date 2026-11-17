#!/usr/bin/env bash
set -euo pipefail
umask 077
package=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
host=com.cpqa.crypto_agent
platform=$(uname -s)

case "$platform" in
    Darwin)
        profiles="$HOME/Library/Application Support"
        root="$profiles/CPQA/Crypto Agent"
        browsers=("Google/Chrome" "Microsoft Edge" "BraveSoftware/Brave-Browser" "Chromium" "Vivaldi")
        ;;
    Linux)
        profiles="${XDG_CONFIG_HOME:-$HOME/.config}"
        root="${XDG_DATA_HOME:-$HOME/.local/share}/cpqa/crypto-agent"
        browsers=("google-chrome" "microsoft-edge" "BraveSoftware/Brave-Browser" "chromium" "vivaldi")
        ;;
    *) printf '%s\n' 'Unsupported platform.' >&2; exit 1 ;;
esac

for file in manifest.json background.js deployment.js; do
    if [[ ! -f "$package/extension/$file" ]]; then
        printf '%s\n' 'Extract the entire Crypto Agent ZIP, then run setup again.' >&2
        exit 1
    fi
done
mkdir -p -- "$root"
destination=$(mktemp -d "$root/install.XXXXXXXX")

replace_directory() {
    local staged="$1" installed="$2" backup="$3"
    if [[ -L "$installed" || ( -e "$installed" && ! -d "$installed" ) ]]; then
        printf 'Unexpected installation path: %s\n' "$installed" >&2
        return 1
    fi
    if [[ -d "$installed" ]]; then
        mv -- "$installed" "$backup"
    fi
    if ! mv -- "$staged" "$installed"; then
        if [[ -d "$backup" && ! -e "$installed" ]]; then
            mv -- "$backup" "$installed"
        fi
        return 1
    fi
}

app=''
if [[ "$platform" == Darwin && -d "$package/CPQA Crypto Agent.app" ]]; then
    source_app="$package/CPQA Crypto Agent.app"
    /usr/bin/codesign --verify --deep --strict "$source_app"
    apps="$HOME/Applications"
    mkdir -p -- "$apps"
    app="$apps/CPQA Crypto Agent.app"
    if [[ -d "$app" && ! -L "$app" ]]; then
        code_identity() {
            /usr/bin/codesign -d --verbose=4 "$1" 2>&1 | sed -n '/^Identifier=/p; /^TeamIdentifier=/p'
        }
        if [[ "$(code_identity "$app")" != "$(code_identity "$source_app")" ]]; then
            printf '%s\n' 'An app from another publisher already uses the Crypto Agent path.' >&2
            exit 1
        fi
    fi
    # Stage beside Applications so the rename keeps the signed bundle intact.
    app_stage=$(mktemp -d "$apps/.cpqa-agent.XXXXXXXX")
    /usr/bin/ditto "$source_app" "$app_stage/new.app"
    /usr/bin/codesign --verify --deep --strict "$app_stage/new.app"
    replace_directory "$app_stage/new.app" "$app" "$app_stage/previous.app"
    path="$app/Contents/Helpers/cpqa-crypto-agent"
    template="$app/Contents/Resources/native-host.json"
else
    if [[ ! -f "$package/runtime/cpqa-crypto-agent" || ! -f "$package/native-host.json" ]]; then
        printf '%s\n' 'Extract the entire Crypto Agent ZIP, then run setup again.' >&2
        exit 1
    fi
    cp -R -- "$package/runtime" "$destination/runtime"
    path="$destination/runtime/cpqa-crypto-agent"
    chmod 700 -- "$path"
    template="$package/native-host.json"
fi

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
done < "$template" > "$destination/native-host.json"

cp -R -- "$package/extension" "$destination/extension"
replace_directory "$destination/extension" "$root/extension" "$destination/previous-extension"
for browser in "${browsers[@]}"; do
    directory="$profiles/$browser/NativeMessagingHosts"
    mkdir -p -- "$directory"
    temporary=$(mktemp "$directory/.$host.XXXXXXXX")
    cp -- "$destination/native-host.json" "$temporary"
    mv -f -- "$temporary" "$directory/$host.json"
done
printf '%s\n' 'Crypto Agent installed.' \
    'In Chrome, Edge, Brave, or Chromium, open Extensions, enable Developer mode, and choose Load unpacked.'
printf 'Select this folder: %s\n' "$root/extension"
if [[ -n "$app" ]]; then
    printf '%s\n' 'In Safari Developer settings, allow unsigned extensions. Enable CPQA under Extensions and allow your CPQA site.'
    if ! /usr/bin/open -g "$app"; then
        printf 'Open the installed app once in Finder to register its Safari extension: %s\n' "$app"
    fi
fi
printf '%s\n' 'Return to CPQA → Security Keys and choose Check Crypto Agent.'
