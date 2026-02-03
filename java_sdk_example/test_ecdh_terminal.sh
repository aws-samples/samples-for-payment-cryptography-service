#!/bin/bash

# Test ECDH Terminal - Set PIN Flow
echo "Testing ECDH Terminal - Set PIN Flow"
echo ""

# Input: Choice 1 (Set PIN), PAN, PIN, then Exit
echo "1
4111111111111111
2983
4" | ./run_example.sh aws.sample.paymentcryptography.terminal.ECDHTerminal
