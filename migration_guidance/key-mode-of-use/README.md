# Re-mode a key from mode of use N

`remode_key.py` changes a symmetric key in AWS Payment Cryptography from TR-31 mode of use `N` (no restrictions) to a mode X9.143 allows for its key usage. Keys exported from payShield often have mode `N`, and many AWS Payment Cryptography operations refuse them. For example, `GenerateCardData` (CW) won't use a mode `N` CVK.

X9.143 only technically allows mode `N` for a very limited set of uses. Any other use of mode `N` is for legacy reasons only, so re-moding is recommended even where AWS Payment Cryptography still accepts the key.

| Key usages | Target modes (default first) |
|------------|------------------------------|
| `B0`, `E0`, `E1`, `E2`, `E4`, `E5`, `E6` | `X` (DeriveKey) |
| `C0`, `M1`, `M3`, `M6`, `M7`, `V1`, `V2` | `C` (Generate + Verify), `G` (Generate), `V` (Verify) |
| `D0`, `K0`, `K1`, `P0` | `B` (Encrypt + Decrypt + Wrap + Unwrap), `E` (Encrypt + Wrap), `D` (Decrypt + Unwrap) |

The script reads the key usage from the TR-31 header, or from the existing key with `--key-arn`, and uses the default mode unless you pass `--mode`. It sets every other `KeyModesOfUse` flag, including `NoRestrictions`, to false.

For which key usages must be re-moded, how the re-wrap works, and usage examples, see [Keys with mode of use N](../payshield-command-mapping.md#keys-with-mode-of-use-n-migrated-from-payshield) in the command mapping.

## Setup

```bash
pip install -r requirements.txt
```

## Required IAM permissions

The script calls these AWS Payment Cryptography control plane actions:

| Action | When | Why |
|--------|------|-----|
| `payment-cryptography:CreateKey` | Always | Creates the temporary AES-256 KEK |
| `payment-cryptography:ImportKey` | Always | Imports the source key (with `--key-block`) and the re-moded key |
| `payment-cryptography:ExportKey` | Always | Exports the key under the temporary KEK with the new mode of use |
| `payment-cryptography:DeleteKey` | Always | Schedules the temporary KEK for deletion, and the original key with `--delete-original` |
| `payment-cryptography:GetKey` | With `--key-arn` | Reads the existing key's usage, ARN and KCV |

`--parse-only` doesn't call AWS and needs no permissions.

Example policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RemodeKey",
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

`Resource` uses `key/*` because the temporary KEK and the re-imported key don't exist until the script runs, so their ARNs aren't known in advance.

The KEK passed with `--kek-arn` must already exist in AWS Payment Cryptography. Importing it (for example with [`import_raw_key_ecdh.py`](../../key-import-export/ecdh/import_app/import_raw_key_ecdh.py)) needs its own permissions, which aren't listed here.
