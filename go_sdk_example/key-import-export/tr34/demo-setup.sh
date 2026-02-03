#!/bin/bash

# TR-34/TR-31 Demo Key Setup Script
# This script imports demonstration keys using TR-34 for KEK and TR-31 for working keys

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

REGION=${AWS_REGION:-"us-east-1"}
PROFILE=${AWS_PROFILE:-"default"}

# Key values
KEK="79ADAEF3212AADCE312ACE422ACCFEFB"  # TDES 2KEY (128-bit)
KEK_3DES="27D43AA69D27D1B1BDD1E0D272392E1F1934E7B3DD352D09"  # TDES 3KEY (192-bit - 24 bytes/48 hex chars)
KEK_AES="9A258BD009C508667F11A04301C6D4EC"  # AES 128-bit
BDK="8A8349794C9EE9A4C2927098F249FED6"
PEK="545E2AADFD5EC42F2F5BE5E3ADC75E9B290252A1A219B380"
MAC="75BDAEF54587CAE6563A5CE57B4B9F9F"
ARQC="6786D3D6F2266E19B67302438ACE7551"

# Aliases for keys
KEK_ALIAS="alias/tr34-kek"
KEK_3DES_ALIAS="alias/tr34-kek-3des"
KEK_AES_ALIAS="alias/tr34-kek-aes"
TDES_BDK_ALIAS="alias/MerchantTerminal_TDES_BDK"
AES_BDK_ALIAS="alias/MerchantTerminal_BDK_AES_128"
PIN_TRANSLATE_PEK_ALIAS="alias/pinTranslateServicePek"
ISSUER_PEK_ALIAS="alias/issuerPek"
ARQC_ALIAS="alias/arqcValidationKey"
MAC_ALIAS="alias/macValidationKey"
PVK_ALIAS="alias/issuerPinValidationKey"

print_status() {
    echo -e "${GREEN}$1${NC}"
}

print_error() {
    echo -e "${RED}$1${NC}"
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command_exists go; then
        print_error "Go is not installed. Please install Go first."
        exit 1
    fi
    
    print_status "Prerequisites check completed."
}

build_tools() {
    print_status "Building TR-34/TR-31 tools..."
    
    if [ ! -f "build/tr34-import" ] || [ ! -f "build/tr31-import" ]; then
        make clean build > /dev/null 2>&1 || {
            print_error "Failed to build tools"
            exit 1
        }
    fi
    
    print_status "Import tools ready."
}

run_tr34_import() {
    local key=$1
    local description=$2
    local algorithm=${3:-"T"}
    local keytype=${4:-"K0"}
    local modeofuse=${5:-"B"}
    local exportmode=${6:-"E"}
    local alias=${7:-""}
    
    local cmd="./build/tr34-import"
    cmd="$cmd --clearkey $key"
    cmd="$cmd --algorithm $algorithm"
    cmd="$cmd --keytype $keytype"
    cmd="$cmd --modeofuse $modeofuse"
    cmd="$cmd --exportmode $exportmode"
    cmd="$cmd --profile $PROFILE"
    cmd="$cmd --region $REGION"

    if [ -n "$alias" ]; then
        cmd="$cmd --alias $alias"
    fi
    
    if [ -n "$PROFILE" ]; then
        cmd="$cmd --profile $PROFILE"
    fi
    
    echo ""
    print_status "*********$description*********"
    echo ""
    
    if output=$($cmd 2>&1); then
        key_arn=$(echo "$output" | grep "Key ARN:" | sed 's/.*Key ARN: *//' | head -1)
        kcv=$(echo "$output" | grep "Key Check Value:" | sed 's/.*Key Check Value: *//' | head -1)
        
        if [ -n "$key_arn" ]; then
            echo "KEK/KPBK/ZMK ARN: $key_arn"
            echo "Reported KCV: $kcv"
            echo ""

            print_status "✓ Import successful"
        else
            echo "$output"
        fi
    else
        print_error "Import failed:"
        echo "$output"
        return 1
    fi
}

run_tr31_import() {
    local kek_arn=$1
    local kek_cleartext=$2
    local kek_algorithm=$3
    local key=$4
    local description=$5
    local keytype=$6
    local modeofuse=$7
    local algorithm=$8
    local alias=$9
    
    local cmd="./build/tr31-import"
    cmd="$cmd --kbpkkey_apcIdentifier $kek_arn"
    cmd="$cmd --kbpk_clearkey $kek_cleartext"
    cmd="$cmd --clearkey $key"
    cmd="$cmd --keytype $keytype"
    cmd="$cmd --modeofuse $modeofuse"
    cmd="$cmd --algorithm $algorithm"
    cmd="$cmd --kek_algorithm $kek_algorithm"
    cmd="$cmd --exportmode E"
    cmd="$cmd --profile $PROFILE"
    cmd="$cmd --region $REGION"
    
    if [ -n "$alias" ]; then
        cmd="$cmd --alias $alias"
    fi
    
    if [ -n "$PROFILE" ]; then
        cmd="$cmd --profile $PROFILE"
    fi
    
    echo ""
    print_status "*********$description*********"
    echo ""
    
    if output=$($cmd 2>&1); then
        key_arn=$(echo "$output" | grep "Key Arn:" | cut -d' ' -f3)
        kcv=$(echo "$output" | grep "Reported KCV:" | cut -d' ' -f3)
        alias_name=$(echo "$output" | grep "Alias:" | cut -d' ' -f2)
        
        if [ -n "$key_arn" ]; then
            echo "Key ARN: $key_arn"
            echo "Reported KCV: $kcv"
            if [ -n "$alias_name" ]; then
                echo "Alias: $alias_name"
            fi

            echo ""
            print_status "✓ Import successful"
        else
            echo "$output"
        fi
    else
        print_error "Import failed:"
        echo "$output"
        return 1
    fi
}

generate_pvk() {
    local pvk_alias="$PVK_ALIAS"
    
    existing_pvk=$(AWS_PROFILE=$PROFILE aws payment-cryptography get-alias \
        --alias-name "$pvk_alias" \
        --region "$REGION" 2>/dev/null || echo "")
    
    if [ -n "$existing_pvk" ]; then
        pvk_arn=$(echo "$existing_pvk" | grep -o '"KeyArn": "[^"]*"' | cut -d'"' -f4)
        
        if [ -n "$pvk_arn" ]; then
            print_warning "PVK already exists with alias: $pvk_alias"
            echo "PVK ARN: $pvk_arn"
            
            key_details=$(AWS_PROFILE=$PROFILE aws payment-cryptography get-key \
                --key-identifier "$pvk_arn" \
                --region "$REGION" 2>/dev/null || echo "")
            
            if [ -n "$key_details" ]; then
                kcv=$(echo "$key_details" | grep -o '"KeyCheckValue": "[^"]*"' | cut -d'"' -f4)
                echo "Reported KCV: $kcv"
            fi
            return 0
        fi
    fi

    local cmd="aws payment-cryptography create-key"
    cmd="$cmd --region $REGION"
    
    if [ -n "$PROFILE" ]; then
        cmd="AWS_PROFILE=$PROFILE $cmd"
    fi
    
    local key_attrs='{"KeyAlgorithm":"TDES_2KEY","KeyClass":"SYMMETRIC_KEY","KeyModesOfUse":{"Generate":true,"Verify":true},"KeyUsage":"TR31_V2_VISA_PIN_VERIFICATION_KEY"}'
    if output=$(eval "$cmd --exportable --key-attributes '$key_attrs'" 2>&1); then
        pvk_arn=$(echo "$output" | grep -o '"KeyArn": "[^"]*"' | cut -d'"' -f4)
        kcv=$(echo "$output" | grep -o '"KeyCheckValue": "[^"]*"' | cut -d'"' -f4)
        
        if [ -n "$pvk_arn" ]; then
            if ! alias_output=$(AWS_PROFILE=$PROFILE aws payment-cryptography create-alias \
                --alias-name "$pvk_alias" \
                --key-arn "$pvk_arn" \
                --region "$REGION" 2>&1); then
                if echo "$alias_output" | grep -q "already exists"; then
                    AWS_PROFILE=$PROFILE aws payment-cryptography update-alias \
                        --alias-name "$pvk_alias" \
                        --key-arn "$pvk_arn" \
                        --region "$REGION" > /dev/null 2>&1
                fi
            fi
            
            echo "PVK ARN: $pvk_arn"
            echo "Alias: $pvk_alias"
            echo "Reported KCV: $kcv"

            echo ""
            print_status "✓ PVK generated successfully"
        else
            print_error "Failed to extract PVK ARN from output"
            echo "$output"
            return 1
        fi
    else
        print_error "Failed to generate PVK"
        echo "$output"
        return 1
    fi
}

main() {
    print_status "========================================"
    print_status "TR-34/TR-31 Complete Demo Key Setup"
    print_status "for AWS Payment Cryptography Service"
    print_status "========================================"
    echo ""
    
    check_prerequisites
    
    build_tools
    
    run_tr34_import "$KEK" "Importing a TDES KEK for importing subsequent keys" "T" "K0" "B" "E" "$KEK_ALIAS"
    
    kek_info=$(AWS_PROFILE=$PROFILE aws payment-cryptography get-alias \
        --alias-name "$KEK_ALIAS" \
        --region "$REGION" 2>/dev/null || echo "")
    
    if [ -n "$kek_info" ]; then
        kek_arn=$(echo "$kek_info" | grep -o '"KeyArn": "[^"]*"' | cut -d'"' -f4)
    else
        kek_arn=""
    fi
    
    if [ -z "$kek_arn" ] || [[ "$kek_arn" == *"Error"* ]]; then
        print_error "Failed to import TDES KEK. Exiting."
        exit 1
    fi
    
    run_tr34_import "$KEK_3DES" "Importing a TDES 3KEY KEK for importing 3DES keys" "T" "K0" "B" "E" "$KEK_3DES_ALIAS"
    
    kek_3des_info=$(AWS_PROFILE=$PROFILE aws payment-cryptography get-alias \
        --alias-name "$KEK_3DES_ALIAS" \
        --region "$REGION" 2>/dev/null || echo "")
    
    if [ -n "$kek_3des_info" ]; then
        kek_3des_arn=$(echo "$kek_3des_info" | grep -o '"KeyArn": "[^"]*"' | cut -d'"' -f4)
    else
        kek_3des_arn=""
    fi
    
    if [ -z "$kek_3des_arn" ] || [[ "$kek_3des_arn" == *"Error"* ]]; then
        print_error "Failed to import TDES 3KEY KEK. Exiting."
        exit 1
    fi
    
    run_tr34_import "$KEK_AES" "Importing an AES KEK for importing AES keys" "A" "K0" "B" "E" "$KEK_AES_ALIAS"
    
    kek_aes_info=$(AWS_PROFILE=$PROFILE aws payment-cryptography get-alias \
        --alias-name "$KEK_AES_ALIAS" \
        --region "$REGION" 2>/dev/null || echo "")
    
    if [ -n "$kek_aes_info" ]; then
        kek_aes_arn=$(echo "$kek_aes_info" | grep -o '"KeyArn": "[^"]*"' | cut -d'"' -f4)
    else
        kek_aes_arn=""
    fi
    
    if [ -z "$kek_aes_arn" ] || [[ "$kek_aes_arn" == *"Error"* ]]; then
        print_error "Failed to import AES KEK. Exiting."
        exit 1
    fi
    
    run_tr31_import "$kek_arn" "$KEK" "T" "$BDK" "Importing TDES BDK for DUKPT" "B0" "X" "T" "$TDES_BDK_ALIAS"

    run_tr31_import "$kek_aes_arn" "$KEK_AES" "A" "$BDK" "Importing AES BDK for DUKPT" "B0" "X" "A" "$AES_BDK_ALIAS"
    
    run_tr31_import "$kek_3des_arn" "$KEK_3DES" "T" "$PEK" "Importing a PEK for communicating with ATM" "P0" "B" "T" "$PIN_TRANSLATE_PEK_ALIAS"
    
    run_tr31_import "$kek_3des_arn" "$KEK_3DES" "T" "$PEK" "Importing a PEK for Pin Translate Service to Issuer communication" "P0" "B" "T" "$ISSUER_PEK_ALIAS"
    
    run_tr31_import "$kek_arn" "$KEK" "T" "$ARQC" "Importing ARQC key for cryptogram validation" "E0" "X" "T" "$ARQC_ALIAS"
    
    run_tr31_import "$kek_arn" "$KEK" "T" "$MAC" "Importing MAC key for MAC verification" "M3" "C" "T" "$MAC_ALIAS"

    echo ""
    print_status "*********Generating PVK*********"
    echo ""

    generate_pvk
    
    echo ""
    print_status "*********Done*********"
    echo ""
    
    print_status "Summary of imported/generated keys:"
    echo "1. TDES 2KEY KEK: $kek_arn"
    echo "2. TDES 3KEY KEK: $kek_3des_arn"
    echo "3. AES KEK: $kek_aes_arn"
    echo "4. TDES BDK: $TDES_BDK_ALIAS"
    echo "5. AES BDK: $AES_BDK_ALIAS"
    echo "6. PIN Translate Service PEK: $PIN_TRANSLATE_PEK_ALIAS"
    echo "7. Issuer PEK: $ISSUER_PEK_ALIAS"
    echo "8. ARQC Validation Key: $ARQC_ALIAS"
    echo "9. MAC Validation Key: $MAC_ALIAS"
    echo "10. PVK (Pin Verification Key): $PVK_ALIAS"
    echo ""
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --region)
            REGION="$2"
            shift 2
            ;;
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --region REGION    AWS region (default: us-east-1)"
            echo "  --profile PROFILE  AWS profile to use"
            echo "  --help            Show this help message"
            echo ""
            echo "This script imports all demonstration keys needed for AWS Payment Cryptography:"
            echo "  1. Uses TR-34 to import a Key Encryption Key (KEK)"
            echo "  2. Uses TR-31 with the KEK to import working keys (BDK, PEK, MAC, ARQC)"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

main