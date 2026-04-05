#!/usr/bin/env bash

set -euo pipefail

script_name="$(basename "$0")"

usage() {
    cat <<EOF
Usage:
  $script_name encrypt --input PATH (--recipient ID | --symmetric) [options]
  $script_name decrypt --input PATH [options]

Commands:
  encrypt    Encrypt a file with GPG
  decrypt    Decrypt a GPG-encrypted file

Common options:
  -i, --input PATH            Input file path
  -o, --output PATH           Output file path
      --homedir PATH          Use a custom GPG home directory
  -h, --help                  Show this help message

Encrypt options:
  -r, --recipient ID          Encrypt for a recipient (repeatable)
  -s, --symmetric             Encrypt with a passphrase instead of a public key
  -a, --armor                 Write ASCII-armored output
      --passphrase-file PATH  Read the symmetric passphrase from a file

Decrypt options:
      --passphrase-file PATH  Read the decryption passphrase from a file

Examples:
  $script_name encrypt --input ./secret.txt --symmetric
  $script_name encrypt --input ./secret.txt --symmetric --passphrase-file ./pass.txt
  $script_name encrypt --input ./secret.txt --recipient alice@example.com --armor
  $script_name decrypt --input ./secret.txt.gpg
EOF
}

die() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

require_value() {
    local option="$1"
    local value="${2:-}"

    [[ -n "$value" ]] || die "$option requires a value"
}

require_gpg() {
    command -v gpg >/dev/null 2>&1 || die "gpg is not installed or not in PATH"
}

default_encrypt_output() {
    local input="$1"
    local armor="$2"

    if [[ "$armor" == "true" ]]; then
        printf '%s.asc\n' "$input"
    else
        printf '%s.gpg\n' "$input"
    fi
}

default_decrypt_output() {
    local input="$1"

    case "$input" in
        *.gpg) printf '%s\n' "${input%.gpg}" ;;
        *.pgp) printf '%s\n' "${input%.pgp}" ;;
        *.asc) printf '%s\n' "${input%.asc}" ;;
        *) printf '%s.decrypted\n' "$input" ;;
    esac
}

encrypt_file() {
    local input=""
    local output=""
    local homedir=""
    local passphrase_file=""
    local armor="false"
    local symmetric="false"
    local -a recipients=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--input)
                require_value "$1" "${2:-}"
                input="$2"
                shift 2
                ;;
            -o|--output)
                require_value "$1" "${2:-}"
                output="$2"
                shift 2
                ;;
            --homedir)
                require_value "$1" "${2:-}"
                homedir="$2"
                shift 2
                ;;
            -r|--recipient)
                require_value "$1" "${2:-}"
                recipients+=("$2")
                shift 2
                ;;
            -s|--symmetric)
                symmetric="true"
                shift
                ;;
            -a|--armor)
                armor="true"
                shift
                ;;
            --passphrase-file)
                require_value "$1" "${2:-}"
                passphrase_file="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown encrypt option: $1"
                ;;
        esac
    done

    [[ -n "$input" ]] || die "encrypt requires --input"
    [[ -f "$input" ]] || die "input file not found: $input"

    if [[ ${#recipients[@]} -gt 0 && "$symmetric" == "true" ]]; then
        die "choose either --recipient or --symmetric, not both"
    fi

    if [[ ${#recipients[@]} -eq 0 && "$symmetric" != "true" ]]; then
        die "encrypt requires either --recipient or --symmetric"
    fi

    if [[ -n "$passphrase_file" && "$symmetric" != "true" ]]; then
        die "--passphrase-file is only supported with --symmetric during encryption"
    fi

    if [[ -n "$passphrase_file" && ! -f "$passphrase_file" ]]; then
        die "passphrase file not found: $passphrase_file"
    fi

    if [[ -z "$output" ]]; then
        output="$(default_encrypt_output "$input" "$armor")"
    fi

    local -a gpg_args=(gpg)

    if [[ -n "$homedir" ]]; then
        gpg_args+=(--homedir "$homedir")
    fi

    gpg_args+=(--output "$output")

    if [[ "$armor" == "true" ]]; then
        gpg_args+=(--armor)
    fi

    if [[ "$symmetric" == "true" ]]; then
        if [[ -n "$passphrase_file" ]]; then
            gpg_args+=(--batch --yes --pinentry-mode loopback --passphrase-file "$passphrase_file")
        fi
        gpg_args+=(--symmetric "$input")
    else
        local recipient
        gpg_args+=(--encrypt)
        for recipient in "${recipients[@]}"; do
            gpg_args+=(--recipient "$recipient")
        done
        gpg_args+=("$input")
    fi

    "${gpg_args[@]}"
    printf 'Encrypted file written to: %s\n' "$output"
}

decrypt_file() {
    local input=""
    local output=""
    local homedir=""
    local passphrase_file=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--input)
                require_value "$1" "${2:-}"
                input="$2"
                shift 2
                ;;
            -o|--output)
                require_value "$1" "${2:-}"
                output="$2"
                shift 2
                ;;
            --homedir)
                require_value "$1" "${2:-}"
                homedir="$2"
                shift 2
                ;;
            --passphrase-file)
                require_value "$1" "${2:-}"
                passphrase_file="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown decrypt option: $1"
                ;;
        esac
    done

    [[ -n "$input" ]] || die "decrypt requires --input"
    [[ -f "$input" ]] || die "input file not found: $input"

    if [[ -n "$passphrase_file" && ! -f "$passphrase_file" ]]; then
        die "passphrase file not found: $passphrase_file"
    fi

    if [[ -z "$output" ]]; then
        output="$(default_decrypt_output "$input")"
    fi

    local -a gpg_args=(gpg)

    if [[ -n "$homedir" ]]; then
        gpg_args+=(--homedir "$homedir")
    fi

    if [[ -n "$passphrase_file" ]]; then
        gpg_args+=(--batch --yes --pinentry-mode loopback --passphrase-file "$passphrase_file")
    fi

    gpg_args+=(--output "$output" --decrypt "$input")

    "${gpg_args[@]}"
    printf 'Decrypted file written to: %s\n' "$output"
}

main() {
    require_gpg

    local command="${1:-}"
    [[ -n "$command" ]] || {
        usage
        exit 1
    }

    shift || true

    case "$command" in
        encrypt)
            encrypt_file "$@"
            ;;
        decrypt)
            decrypt_file "$@"
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            die "unknown command: $command"
            ;;
    esac
}

main "$@"
