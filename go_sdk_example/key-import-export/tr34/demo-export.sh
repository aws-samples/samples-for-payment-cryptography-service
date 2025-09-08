#!/bin/bash

# TR-34/TR-31 Key Export Demo Script
# This script demonstrates exporting keys from AWS Payment Cryptography Service

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

REGION=${AWS_REGION:-"us-east-1"}
PROFILE=${AWS_PROFILE:-"default"}

# Key to export
KEK_ALIAS="alias/tr34-kek"
KEK_3DES_ALIAS="alias/tr34-kek-3des"
KEK_AES_ALIAS="alias/tr34-kek-aes"
KEYS_TO_EXPORT=(
    "alias/MerchantTerminal_TDES_BDK"
    "alias/MerchantTerminal_BDK_AES_128"
    "alias/pinTranslateServicePek"
    "alias/issuerPek"
    "alias/arqcValidationKey"
    "alias/macValidationKey"
    "alias/issuerPinValidationKey"
)

print_status() {
    echo -e "${GREEN}$1${NC}"
}

print_error() {
    echo -e "${RED}ERROR: $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command_exists go; then
        print_error "Go is not installed. Please install Go 1.21 or later."
        exit 1
    fi
    
    if ! command_exists aws; then
        print_error "AWS CLI is not installed. Please install AWS CLI."
        exit 1
    fi
    
    print_status "Prerequisites check completed."
}

build_tools() {
    print_status "Checking export tools..."
    
    if [ ! -f "build/tr34-export" ] || [ ! -f "build/tr31-export" ]; then
        print_status "Building TR-34/TR-31 export tools..."
        make clean build > /dev/null 2>&1 || {
            print_error "Failed to build tools"
            exit 1
        }
    fi
    
    print_status "Export tools ready."
}


export_tr34_key() {
    local key_alias=$1
    local description=$2
    
    echo ""
    print_status "*********$description*********"
    echo "Key alias: $key_alias"

    if output=$(AWS_PROFILE=$PROFILE ./build/tr34-export --keyalias "$key_alias" --region "$REGION" 2>&1); then
        echo "$output"

        echo ""
        print_status "✓ TR-34 export successful"
    else
        print_error "Failed to export key using TR-34"
        echo "$output"
    fi
}

export_tr31_key() {
    local kek_alias=$1
    local key_alias=$2
    local description=$3
    
    echo ""
    print_status "*********$description*********"
    echo "Exporting: $key_alias"
    echo "Using KEK: $kek_alias"

    if output=$(./build/tr31-export --kek "$kek_alias" --key "$key_alias" --region "$REGION" --profile "$PROFILE" 2>&1); then
        echo "$output"

        echo ""
        print_status "✓ TR-31 export successful"
    else
        if echo "$output" | grep -q "insufficient for the operation"; then
            print_warning "Cannot export with TDES KEK (insufficient key strength)"
        else
            print_error "Failed to export key using TR-31"
            echo "$output"
        fi
    fi
}

main() {
    print_status "========================================"
    print_status "TR-34/TR-31 Key Export Demo"
    print_status "for AWS Payment Cryptography Service"
    print_status "========================================"
    echo ""
    
    check_prerequisites
    
    build_tools
    
    echo ""
    print_status "Starting key export process..."
    echo ""

    export_tr34_key "$KEK_ALIAS" "Exporting TDES 2KEY KEK using TR-34"
    export_tr34_key "$KEK_3DES_ALIAS" "Exporting TDES 3KEY KEK using TR-34"
    export_tr34_key "$KEK_AES_ALIAS" "Exporting AES KEK using TR-34"

    kek_info=$(AWS_PROFILE=$PROFILE aws payment-cryptography get-alias \
        --alias-name "$KEK_ALIAS" \
        --region "$REGION" 2>/dev/null || echo "")

    if [ -n "$kek_info" ]; then
        kek_arn=$(echo "$kek_info" | grep -o '"KeyArn": "[^"]*"' | cut -d'"' -f4)
    else
        kek_arn=""
    fi

    kek_3des_info=$(AWS_PROFILE=$PROFILE aws payment-cryptography get-alias \
        --alias-name "$KEK_3DES_ALIAS" \
        --region "$REGION" 2>/dev/null || echo "")

    if [ -n "$kek_3des_info" ]; then
        kek_3des_arn=$(echo "$kek_3des_info" | grep -o '"KeyArn": "[^"]*"' | cut -d'"' -f4)
    else
        kek_3des_arn=""
    fi

    kek_aes_info=$(AWS_PROFILE=$PROFILE aws payment-cryptography get-alias \
        --alias-name "$KEK_AES_ALIAS" \
        --region "$REGION" 2>/dev/null || echo "")

    if [ -n "$kek_aes_info" ]; then
        kek_aes_arn=$(echo "$kek_aes_info" | grep -o '"KeyArn": "[^"]*"' | cut -d'"' -f4)
    else
        kek_aes_arn=""
    fi
    
    if [ -z "$kek_arn" ]; then
        print_error "Could not find TDES KEK with alias: $KEK_ALIAS"
        print_warning "Skipping TR-31 exports"
    else
        for key_alias in "${KEYS_TO_EXPORT[@]}"; do
            key_exists=$(AWS_PROFILE=$PROFILE aws payment-cryptography get-alias \
                --alias-name "$key_alias" \
                --region "$REGION" 2>/dev/null || echo "")
            
            if [ -n "$key_exists" ]; then
                if [[ "$key_alias" == *"AES"* ]] && [ -n "$kek_aes_arn" ]; then
                    export_tr31_key "$kek_aes_arn" "$key_alias" "Exporting $(basename $key_alias) with AES KEK"
                elif [[ "$key_alias" == *"Pek"* ]] && [ -n "$kek_3des_arn" ]; then
                    export_tr31_key "$kek_3des_arn" "$key_alias" "Exporting $(basename $key_alias) with TDES 3KEY KEK"
                else
                    export_tr31_key "$kek_arn" "$key_alias" "Exporting $(basename $key_alias) with TDES 2KEY KEK"
                fi
            else
                echo ""
                echo -e "${YELLOW}****************************************${NC}"
                print_warning "Key not found: $key_alias (skipping)"
                echo -e "${YELLOW}****************************************${NC}"
                echo ""
            fi
        done
    fi
    
    echo ""
    print_status "========================================"
    print_status "Export Complete"
    print_status "========================================"
    echo ""
    
    echo -e "${YELLOW}SECURITY NOTES:${NC}"
    echo "- TR-34 exports show clear keys (for demonstration purposes only)"
    echo "- TR-31 exports show encrypted key blocks"
    echo "- Never share clear keys in production environments"
    echo ""
    echo -e "${YELLOW}KEY STRENGTH REQUIREMENTS:${NC}"
    echo "- TDES 2KEY KEK can only export keys up to TDES 2KEY strength"
    echo "- TDES 3KEY KEK is required to export TDES 3KEY keys (like PEKs)"
    echo "- AES KEK is required to export AES keys"
    
    echo ""
    print_status "*********Done*********"
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --region REGION     AWS region (default: us-east-1)"
    echo "  --profile PROFILE   AWS profile to use"
    echo "  --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  # Export using default settings"
    echo "  $0"
    echo ""
    echo "  # Export using specific AWS profile and region"
    echo "  $0 --profile default --region us-west-2"
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
            show_usage
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