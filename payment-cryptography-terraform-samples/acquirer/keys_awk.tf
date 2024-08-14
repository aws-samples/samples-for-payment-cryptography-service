resource "aws_paymentcryptography_key" "awk-key" {
  exportable = true
  key_attributes {
    key_algorithm = "TDES_3KEY"
    key_class     = "SYMMETRIC_KEY"
    key_usage     = "TR31_P0_PIN_ENCRYPTION_KEY"
    key_modes_of_use {
      encrypt = true
      decrypt = true
      wrap    = true
      unwrap  = true

    }
  }
}

resource "aws_paymentcryptography_key_alias" "awk-key" {
  alias_name = "alias/awk-key"
  key_arn    = aws_paymentcryptography_key.bdk-key.arn
}