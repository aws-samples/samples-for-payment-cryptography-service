# Sample Roles

| Service | Purpose | Policy | Allowed Actions | Notes |
|---------|---------|--------|----------------|-------|
| PaymentAuthProcessor | Processes Auths | PaymentAuthProcessorPolicy | VerifyAuthRequestCrypto, VerifyPinData, VerifyCardData | Performs Main Card Validation Processes and Procedures |
| PaymentNetworkService | Handles connections to networks. Connects to cryptography... | NetworkKeyExchangePolicy | CreateKey, ExportKey, GenerateMac, VerifyMac | Limit key creation to payment-cryptography:KeyUsage = TR31_P0_PIN_ENCRYPTION_KEY. Export can restrict based on tags (PURPOSE=NETWORK_DYNAMIC_KEYS) to prevent this role from exporting or using any other keys. NOTE: Traditional HSM don't have this level of granularity |
| | - Handles Dynamic Key Exchange with networks for pin transactions | | | |
| | - generate/verify MAC when networks require it | | | |
| BinSetupProcessor | Creates New BINs using a MC template that creates key "bundle". Tag keys with BIN to keep structured. | BinSetupPolicy | CreateKey, ExportKey, ImportKey | Create and Export key if this service is generating keys. ImportKey if this service is ingesting keys created elsewhere by a card issuance platform. |
| KeyManagementOperator | Transfer Initial Key (KEK) to card networks. Exchange working keys with network such as those used for ODO processing (CVK for card networks, IMK for other networks) | OperatorRole | CreateKey, ExportKey, ImportKey | |