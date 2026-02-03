#!/bin/bash

# Comprehensive test for ECDH PIN flows
# Tests both ISO Format 0 and ISO Format 4

set -e

PAN="4111111111111111"
PIN="1234"

echo "=== ECDH PIN Flow Testing ==="
echo "PAN: $PAN"
echo "PIN: $PIN"
echo ""

# Function to run terminal and capture output
run_terminal_test() {
    local input="$1"
    local test_name="$2"
    
    echo "========================================="
    echo "$test_name"
    echo "========================================="
    
    # Run the terminal with input
    output=$(echo -e "$input" | timeout 30 ./run_example.sh aws.sample.paymentcryptography.terminal.ECDHTerminal 2>&1 || true)
    
    echo "$output"
    echo ""
    
    # Return the output for further processing
    echo "$output"
}

# Test 1: ISO Format 4 - Set PIN
echo ""
echo "TEST 1: ISO Format 4 - Set PIN"
output_format4_set=$(run_terminal_test "1\n$PAN\n$PIN\n6" "ISO Format 4 - Set PIN")

# Extract PEK encrypted PIN block from output
pek_block_format4=$(echo "$output_format4_set" | grep "PEK Encrypted PIN Block:" | awk '{print $NF}')

if [ -n "$pek_block_format4" ]; then
    echo "✓ Captured PEK Block (Format 4): $pek_block_format4"
    echo ""
    
    # Test 2: ISO Format 4 - Reveal PIN
    echo "TEST 2: ISO Format 4 - Reveal PIN"
    sleep 2
    output_format4_reveal=$(run_terminal_test "2\n$PAN\n$pek_block_format4\n6" "ISO Format 4 - Reveal PIN")
    
    # Check if PIN was revealed correctly
    if echo "$output_format4_reveal" | grep -q "Actual PIN: $PIN"; then
        echo "✓ ISO Format 4 - PIN revealed correctly: $PIN"
    else
        echo "✗ ISO Format 4 - PIN reveal failed"
    fi
else
    echo "✗ Failed to capture PEK block for Format 4"
fi

echo ""
echo "Waiting 3 seconds before Format 0 tests..."
sleep 3

# Test 3: ISO Format 0 - Set PIN
echo ""
echo "TEST 3: ISO Format 0 - Set PIN"
output_format0_set=$(run_terminal_test "4\n$PAN\n$PIN\n6" "ISO Format 0 - Set PIN")

# Extract PEK encrypted PIN block from output
pek_block_format0=$(echo "$output_format0_set" | grep "PEK Encrypted PIN Block:" | awk '{print $NF}')

if [ -n "$pek_block_format0" ]; then
    echo "✓ Captured PEK Block (Format 0): $pek_block_format0"
    echo ""
    
    # Test 4: ISO Format 0 - Reveal PIN
    echo "TEST 4: ISO Format 0 - Reveal PIN"
    sleep 2
    output_format0_reveal=$(run_terminal_test "5\n$PAN\n$pek_block_format0\n6" "ISO Format 0 - Reveal PIN")
    
    # Check if PIN was revealed correctly
    if echo "$output_format0_reveal" | grep -q "Actual PIN: $PIN"; then
        echo "✓ ISO Format 0 - PIN revealed correctly: $PIN"
    else
        echo "✗ ISO Format 0 - PIN reveal failed"
    fi
else
    echo "✗ Failed to capture PEK block for Format 0"
fi

echo ""
echo "========================================="
echo "Testing Complete"
echo "========================================="
