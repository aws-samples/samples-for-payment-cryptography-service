# Re-mode a CVK from mode of use N

`remode_cvk.py` changes a CVK (TR-31 key usage `C0`) in AWS Payment Cryptography from mode of use `N` (no restrictions) to `C` (Generate + Verify), `G` (Generate) or `V` (Verify), so you can use it with `GenerateCardData` (CW) and `VerifyCardData` (CY).

For background on why this is needed and usage examples, see [CVK mode of use N](../payshield-command-mapping.md#cvk-mode-of-use-n-migrated-from-payshield) in the command mapping.

## Setup

```bash
pip install -r requirements.txt
```

## Required IAM permissions

The script calls these AWS Payment Cryptography control plane actions:

| Action | When | Why |
|--------|------|-----|
| `payment-cryptography:CreateKey` | Always | Creates the temporary AES-256 KEK |
| `payment-cryptography:ImportKey` | Always | Imports the source CVK (with `--key-block`) and the re-moded CVK |
| `payment-cryptography:ExportKey` | Always | Exports the CVK under the temporary KEK with the new mode of use |
| `payment-cryptography:DeleteKey` | Always | Schedules the temporary KEK for deletion, and the original CVK with `--delete-original` |
| `payment-cryptography:GetKey` | With `--cvk-arn` | Reads the existing CVK's ARN and KCV |

`--parse-only` doesn't call AWS and needs no permissions.

Example policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RemodeCvk",
      "Effect": "Allow",
      "Action": [
        "payment-cryptography:CreateKey",
        "payment-cryptography:ImportKey",
        "payment-cryptography:ExportKey",
        "payment-cryptography:DeleteKey",
        "payment-cryptography:GetKey"
      ],
      "Resource": "arn:aws:payment-cryptography:<region>:<account-id>:key/*"
    }
  ]
}
```

`Resource` uses `key/*` because the temporary KEK and the re-imported CVK don't exist until the script runs, so their ARNs aren't known in advance.

The KEK passed with `--kek-arn` must already exist in AWS Payment Cryptography. Importing it (for example with [`import_raw_key_ecdh.py`](../../key-import-export/ecdh/import_app/import_raw_key_ecdh.py)) needs its own permissions, which aren't listed here.
