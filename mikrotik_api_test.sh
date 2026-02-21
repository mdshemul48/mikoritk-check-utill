#!/bin/bash

IP="$1"
PORT="$2"
USER="$3"
PASS="$4"

if [ -z "$IP" ] || [ -z "$PORT" ] || [ -z "$USER" ] || [ -z "$PASS" ]; then
    echo "Usage: $0 <ip> <port> <username> <password>"
    exit 1
fi

########################################
# Encode word length (MikroTik format)
########################################
encode_length() {
    local len=$1

    if (( len < 0x80 )); then
        printf '%b' "$(printf '\\x%02x' "$len")"
    elif (( len < 0x4000 )); then
        len=$((len | 0x8000))
        printf '%b' "$(printf '\\x%02x\\x%02x' $(( (len >> 8) & 0xFF )) $(( len & 0xFF )))"
    elif (( len < 0x200000 )); then
        len=$((len | 0xC00000))
        printf '%b' "$(printf '\\x%02x\\x%02x\\x%02x' \
            $(( (len >> 16) & 0xFF )) $(( (len >> 8) & 0xFF )) $(( len & 0xFF )))"
    else
        printf '%b' $'\\xF0\\x00\\x00\\x00\\x00'
    fi
}

########################################
# Send word
########################################
send_word() {
    local word="$1"
    local len=${#word}
    encode_length $len >&3
    printf '%s' "$word" >&3
}

########################################
# End sentence
########################################
end_sentence() {
    printf "\x00" >&3
}

########################################
# Connect
########################################
exec 3<>/dev/tcp/$IP/$PORT || {
    echo "❌ Cannot connect to $IP:$PORT"
    exit 1
}

echo "✅ Connected to MikroTik API"

########################################
# Login (RouterOS v6/v7)
########################################
send_word "/login"
send_word "=name=$USER"
send_word "=password=$PASS"
end_sentence

sleep 1
cat <&3 &
sleep 1

########################################
# Get PPP Secrets
########################################
echo "📄 Getting PPP Secrets..."

send_word "/ppp/secret/print"
end_sentence

sleep 1
cat <&3 &
sleep 1

########################################
# Get Active PPPoE
########################################
echo "📡 Getting Active PPPoE..."

send_word "/ppp/active/print"
end_sentence

sleep 1
cat <&3 &
sleep 1

echo "🎉 Done."