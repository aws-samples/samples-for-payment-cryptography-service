#!/bin/bash

echo "Testing ECDH Service Endpoints..."
echo ""

echo "1. Testing /certificates endpoint:"
curl -s http://localhost:8080/ecdh-service/certificates | python3 -m json.tool
echo ""
echo ""

echo "2. Testing /setPin endpoint (should return not_implemented):"
curl -s -X POST http://localhost:8080/ecdh-service/setPin \
  -d "encryptedPinBlock=test" \
  -d "pan=test" \
  -d "csr=test" \
  -d "sharedInfo=test" \
  -d "signedCertificate=test" \
  -d "certificateChain=test" | python3 -m json.tool
echo ""
