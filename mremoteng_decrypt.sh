#!/usr/bin/env bash

# mRemoteNG Configuration File Decryptor

PASSWORD="mR3m"
CSV_OUTPUT=false
CONFIG_FILE=""
DEBUG=false

usage() {
    cat <<EOF
Usage: $0 <config_file> [OPTIONS]

Options:
    -p, --password PASSWORD   Master password (default: mR3m)
    --csv                     Output CSV
    --debug                   Debug output
    -h, --help                Help
EOF
    exit 1
}

debug() {
    [[ "$DEBUG" == true ]] && echo "[DEBUG] $*" >&2
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--password) PASSWORD="$2"; shift 2 ;;
        --csv) CSV_OUTPUT=true; shift ;;
        --debug) DEBUG=true; shift ;;
        -h|--help) usage ;;
        *) CONFIG_FILE="$1"; shift ;;
    esac
done

[[ -z "$CONFIG_FILE" ]] && { echo "Error: config_file required"; exit 1; }
[[ ! -f "$CONFIG_FILE" ]] && { echo "Error: File not found"; exit 1; }

# Compile CBC helper (stdin version)
compile_cbc() {
    local path="/tmp/mremote_cbc_$$"
    cat > "$path.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

int main(int argc, char *argv[]) {
    if (argc != 2) return 1;
    
    char *password = argv[1];
    
    // Read hex from stdin
    size_t cap = 1024, len = 0;
    char *hex = malloc(cap);
    int c;
    while ((c = getchar()) != EOF) {
        if (len + 1 >= cap) {
            cap *= 2;
            hex = realloc(hex, cap);
        }
        hex[len++] = c;
    }
    hex[len] = '\0';
    
    size_t data_len = len / 2;
    unsigned char *data = malloc(data_len);
    for(size_t i=0; i<data_len; i++) sscanf(hex+2*i, "%2hhx", &data[i]);
    
    unsigned char *iv = data;
    unsigned char *ct = data + 16;
    size_t ct_len = data_len - 16;
    
    unsigned char key[16];
    MD5((unsigned char*)password, strlen(password), key);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    
    unsigned char *pt = malloc(ct_len + 16);
    int tmp, pt_len;
    
    EVP_DecryptUpdate(ctx, pt, &tmp, ct, ct_len);
    pt_len = tmp;
    
    if(EVP_DecryptFinal_ex(ctx, pt+tmp, &tmp) != 1) return 1;
    pt_len += tmp;
    
    fwrite(pt, 1, pt_len, stdout);
    
    free(pt); free(data); free(hex);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
EOF
    gcc -o "$path" "$path.c" -lcrypto 2>/dev/null || return 1
    rm -f "$path.c"
    echo "$path"
}

# Compile GCM helper (stdin version)
compile_gcm() {
    local path="/tmp/mremote_gcm_$$"
    cat > "$path.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

int main(int argc, char *argv[]) {
    if (argc != 2) return 1;
    
    char *password = argv[1];
    
    // Read hex from stdin
    size_t cap = 1024, len = 0;
    char *hex = malloc(cap);
    int c;
    while ((c = getchar()) != EOF) {
        if (len + 1 >= cap) {
            cap *= 2;
            hex = realloc(hex, cap);
        }
        hex[len++] = c;
    }
    hex[len] = '\0';
    
    size_t data_len = len / 2;
    unsigned char *data = malloc(data_len);
    for(size_t i=0; i<data_len; i++) sscanf(hex+2*i, "%2hhx", &data[i]);
    
    unsigned char *salt = data;
    unsigned char *nonce = data + 16;
    unsigned char *ct = data + 32;
    size_t ct_len = data_len - 32 - 16;
    unsigned char *tag = data + data_len - 16;
    
    unsigned char key[32];
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, 16, 1000, EVP_sha1(), 32, key);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    
    int tmp;
    EVP_DecryptUpdate(ctx, NULL, &tmp, salt, 16);
    
    unsigned char *pt = malloc(ct_len);
    EVP_DecryptUpdate(ctx, pt, &tmp, ct, ct_len);
    int pt_len = tmp;
    
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    
    if(EVP_DecryptFinal_ex(ctx, pt+tmp, &tmp) != 1) return 1;
    pt_len += tmp;
    
    fwrite(pt, 1, pt_len, stdout);
    
    free(pt); free(data); free(hex);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
EOF
    gcc -o "$path" "$path.c" -lcrypto 2>/dev/null || return 1
    rm -f "$path.c"
    echo "$path"
}

# Decrypt function - pipes hex data to stdin
decrypt() {
    local mode="$1"
    local hex_data="$2"
    
    debug "Decrypt called: mode=$mode, data_len=${#hex_data}"
    
    if [[ "$mode" == "CBC" ]]; then
        printf '%s' "$hex_data" | "$CBC_HELPER" "$PASSWORD" 2>/dev/null
    else
        printf '%s' "$hex_data" | "$GCM_HELPER" "$PASSWORD" 2>/dev/null
    fi
}

# Read config file
CONF=$(<"$CONFIG_FILE")

# Detect mode
MODE="CBC"
if grep -q 'BlockCipherMode="GCM"' <<<"$CONF"; then
    MODE="GCM"
fi

debug "Mode: $MODE"

# Compile helpers
if [[ "$MODE" == "GCM" ]]; then
    GCM_HELPER=$(compile_gcm)
    CBC_HELPER=""
    [[ -z "$GCM_HELPER" ]] && { echo "Failed to compile GCM helper"; exit 1; }
    debug "GCM helper: $GCM_HELPER"
else
    CBC_HELPER=$(compile_cbc)
    GCM_HELPER=""
    [[ -z "$CBC_HELPER" ]] && { echo "Failed to compile CBC helper"; exit 1; }
    debug "CBC helper: $CBC_HELPER"
fi

# Handle full file encryption
if grep -q 'FullFileEncryption="true"' <<<"$CONF"; then
    debug "Full file encryption detected"
    
    CIPHER_B64=$(sed -n 's/.*ConfVersion="[^"]*">\([^<]*\)<\/mrng:Connections>.*/\1/p' <<<"$CONF")
    CIPHER_HEX=$(printf '%s' "$CIPHER_B64" | base64 -d | xxd -p -c 999999 | tr -d '\n')
    
    CONF=$(decrypt "$MODE" "$CIPHER_HEX")
    EXIT_CODE=$?
    
    if [[ -z "$CONF" ]]; then
        echo "Error: Failed to decrypt file. Wrong password?"
        exit 1
    fi
    
    debug "File decrypted successfully"
fi

# Output CSV header
[[ "$CSV_OUTPUT" == true ]] && echo "Name,Hostname,Username,Password"

# Process nodes - match both <Node and <mrng:Node patterns
debug "Extracting nodes from XML..."

# Use a more robust pattern to match Node elements
mapfile -t NODES < <(grep -oE '<[^>]*Node[^>]+>' <<<"$CONF")

debug "Found ${#NODES[@]} nodes"

for node in "${NODES[@]}"; do
    # Extract attributes
    name=$(echo "$node" | grep -oP ' Name="\K[^"]*' 2>/dev/null || echo "")
    username=$(echo "$node" | grep -oP ' Username="\K[^"]*' 2>/dev/null || echo "")
    hostname=$(echo "$node" | grep -oP ' Hostname="\K[^"]*' 2>/dev/null || echo "")
    pw_b64=$(echo "$node" | grep -oP ' Password="\K[^"]*' 2>/dev/null || echo "")
    
    # Skip if no name (probably not a real connection node)
    [[ -z "$name" ]] && continue
    
    if [[ "$DEBUG" == true ]]; then
        debug "Node: name='$name', host='$hostname', user='$username', pw_len=${#pw_b64}"
    fi
    
    password=""
    if [[ -n "$pw_b64" ]]; then
        data_hex=$(printf '%s' "$pw_b64" | base64 -d 2>/dev/null | xxd -p -c 999999 | tr -d '\n')
        if [[ -n "$data_hex" ]]; then
            password=$(decrypt "$MODE" "$data_hex")
            [[ "$DEBUG" == true && -n "$password" ]] && debug "  -> Password decrypted (${#password} chars)"
        fi
    fi
    
    # Output the node
    if [[ "$CSV_OUTPUT" == true ]]; then
        printf '"%s","%s","%s","%s"\n' "$name" "$hostname" "$username" "$password"
    else
        printf 'Name: %s\nHostname: %s\nUsername: %s\nPassword: %s\n\n' "$name" "$hostname" "$username" "$password"
    fi
done

# Cleanup
rm -f "$CBC_HELPER" "$GCM_HELPER"
