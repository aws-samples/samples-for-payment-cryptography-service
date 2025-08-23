#!/bin/bash

# TR-34/TR-31 Demo Cleanup Script
# This script removes all demonstration keys created by demo-setup.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

REGION=${AWS_REGION:-"us-east-1"}
PROFILE=${AWS_PROFILE:-"default"}
DRY_RUN=false
FORCE=false

# Key aliases to clean up
KEY_ALIASES=(
    "alias/tr34-kek"
    "alias/tr34-kek-3des"
    "alias/tr34-kek-aes"
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
    
    if ! command_exists aws; then
        print_error "AWS CLI is not installed. Please install AWS CLI."
        exit 1
    fi
    
    local aws_cmd="aws sts get-caller-identity --region $REGION"
    if [ -n "$PROFILE" ]; then
        aws_cmd="AWS_PROFILE=$PROFILE $aws_cmd"
    fi
    
    if ! eval $aws_cmd >/dev/null 2>&1; then
        print_error "AWS credentials not configured or invalid. Please configure AWS credentials."
        exit 1
    fi
    
    print_status "Prerequisites check completed."
}

get_key_arn_from_alias() {
    local alias_name=$1
    
    local cmd="aws payment-cryptography get-alias"
    cmd="$cmd --alias-name $alias_name"
    cmd="$cmd --region $REGION"
    
    if [ -n "$PROFILE" ]; then
        cmd="AWS_PROFILE=$PROFILE $cmd"
    fi
    
    alias_info=$(eval $cmd 2>/dev/null || echo "")
    
    if [ -n "$alias_info" ]; then
        key_arn=$(echo "$alias_info" | grep -o '"KeyArn": "[^"]*"' | cut -d'"' -f4)
        echo "$key_arn"
    fi
}

delete_key() {
    local key_arn=$1
    local alias_name=$2
    local delete_days=3
    
    if [ "$DRY_RUN" = true ]; then
        print_warning "[DRY RUN] Would delete key: $alias_name ($key_arn)"
        return 0
    fi
    
    local cmd="aws payment-cryptography delete-key"
    cmd="$cmd --key-identifier $key_arn"
    cmd="$cmd --delete-key-in-days $delete_days"
    cmd="$cmd --region $REGION"
    
    if [ -n "$PROFILE" ]; then
        cmd="AWS_PROFILE=$PROFILE $cmd"
    fi
    
    output=$(eval $cmd 2>&1)
    
    if [ $? -eq 0 ]; then
        print_status "✓ Scheduled deletion for $alias_name in $delete_days days"
        
        deletion_date=$(echo "$output" | grep -o '"DeletionDate": "[^"]*"' | cut -d'"' -f4)
        if [ -n "$deletion_date" ]; then
            echo "  Deletion date: $deletion_date"
        fi
    else
        if echo "$output" | grep -q "ScheduleKeyDeletionPending"; then
            print_warning "Key $alias_name is already scheduled for deletion"
        elif echo "$output" | grep -q "ResourceNotFoundException"; then
            print_warning "Key $alias_name not found (already deleted?)"
        else
            print_error "Failed to delete key $alias_name"
            echo "$output"
        fi
    fi
}

delete_alias() {
    local alias_name=$1
    
    if [ "$DRY_RUN" = true ]; then
        print_warning "[DRY RUN] Would delete alias: $alias_name"
        return 0
    fi
    
    local cmd="aws payment-cryptography delete-alias"
    cmd="$cmd --alias-name $alias_name"
    cmd="$cmd --region $REGION"
    
    if [ -n "$PROFILE" ]; then
        cmd="AWS_PROFILE=$PROFILE $cmd"
    fi
    
    output=$(eval $cmd 2>&1)
    
    if [ $? -eq 0 ]; then
        print_status "✓ Deleted alias: $alias_name"
    else
        if echo "$output" | grep -q "ResourceNotFoundException"; then
            return 0
        else
            print_warning "Could not delete alias $alias_name (may not exist)"
        fi
    fi
}

list_keys_to_delete() {
    print_status "Keys that will be deleted:"
    echo ""
    
    local found_keys=false
    
    for alias in "${KEY_ALIASES[@]}"; do
        key_arn=$(get_key_arn_from_alias "$alias")
        
        if [ -n "$key_arn" ]; then
            found_keys=true
            echo "  - $alias"
            echo "    ARN: $key_arn"
            
            local cmd="aws payment-cryptography get-key"
            cmd="$cmd --key-identifier $key_arn"
            cmd="$cmd --region $REGION"
            
            if [ -n "$PROFILE" ]; then
                cmd="AWS_PROFILE=$PROFILE $cmd"
            fi
            
            key_info=$(eval $cmd 2>/dev/null || echo "")
            
            if [ -n "$key_info" ]; then
                key_state=$(echo "$key_info" | grep -o '"KeyState": "[^"]*"' | cut -d'"' -f4)
                if [ -n "$key_state" ]; then
                    echo "    State: $key_state"
                fi
                
                kcv=$(echo "$key_info" | grep -o '"KeyCheckValue": "[^"]*"' | cut -d'"' -f4)
                if [ -n "$kcv" ]; then
                    echo "    KCV: $kcv"
                fi
            fi
            echo ""
        fi
    done
    
    if [ "$found_keys" = false ]; then
        print_warning "No keys found to delete"
        return 1
    fi
    
    return 0
}

confirm_deletion() {
    if [ "$FORCE" = true ]; then
        return 0
    fi
    
    echo ""
    print_warning "This will schedule the deletion of all demo keys created by demo-setup.sh"
    print_warning "Keys will be permanently deleted after the waiting period (3 days minimum)"
    echo ""
    read -p "Are you sure you want to continue? (yes/no): " confirmation
    
    if [ "$confirmation" != "yes" ]; then
        print_status "Cleanup cancelled"
        exit 0
    fi
}

main() {
    print_status "========================================"
    print_status "TR-34/TR-31 Demo Cleanup"
    print_status "for AWS Payment Cryptography Service"
    print_status "========================================"
    echo ""
    
    check_prerequisites
    
    echo ""
    
    if ! list_keys_to_delete; then
        print_status "No cleanup needed"
        exit 0
    fi
    
    if [ "$DRY_RUN" = false ]; then
        confirm_deletion
    fi
    
    echo ""
    print_status "Starting cleanup process..."
    echo ""
    
    for alias in "${KEY_ALIASES[@]}"; do
        print_status "Processing: $alias"
        
        key_arn=$(get_key_arn_from_alias "$alias")
        
        if [ -n "$key_arn" ]; then
            delete_alias "$alias"
            
            delete_key "$key_arn" "$alias"
        else
            print_warning "Key not found: $alias (skipping)"
        fi
        
        echo ""
    done
    
    if [ -d "exported-keys" ] && [ "$DRY_RUN" = false ]; then
        print_status "Cleaning up exported-keys directory..."
        if [ "$FORCE" = true ]; then
            rm -rf exported-keys
            print_status "✓ Removed exported-keys directory"
        else
            read -p "Remove exported-keys directory? (yes/no): " remove_exports
            if [ "$remove_exports" = "yes" ]; then
                rm -rf exported-keys
                print_status "✓ Removed exported-keys directory"
            fi
        fi
    fi
    
    echo ""
    print_status "========================================"
    print_status "Cleanup Summary"
    print_status "========================================"
    
    if [ "$DRY_RUN" = true ]; then
        print_warning "DRY RUN completed - no changes were made"
        echo "Run without --dry-run to actually delete the keys"
    else
        print_status "✓ All demo keys have been scheduled for deletion"
        print_warning "Keys will be deleted after the waiting period (3 days)"
        echo ""
        echo "To cancel deletion before the waiting period expires, use:"
        echo "  aws payment-cryptography restore-key --key-identifier <KEY_ARN>"
    fi
    
    echo ""
    print_status "*********Done*********"
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --region REGION   AWS region (default: us-east-1)"
    echo "  --profile PROFILE AWS profile to use"
    echo "  --dry-run         Show what would be deleted without making changes"
    echo "  --force           Skip confirmation prompts"
    echo "  --help            Show this help message"
    echo ""
    echo "This script removes all demonstration keys created by demo-setup.sh"
    echo ""
    echo "Examples:"
    echo "  # Preview what will be deleted (dry run)"
    echo "  $0 --dry-run"
    echo ""
    echo "  # Delete keys with confirmation"
    echo "  $0"
    echo ""
    echo "  # Delete keys without confirmation"
    echo "  $0 --force"
    echo ""
    echo "  # Delete keys in specific region with profile"
    echo "  $0 --profile default --region us-west-2"
    echo ""
    echo "Security Notes:"
    echo "  - Keys are scheduled for deletion with a 3-day waiting period"
    echo "  - Deletion can be cancelled during the waiting period"
    echo "  - Once deleted, keys cannot be recovered"
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
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
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