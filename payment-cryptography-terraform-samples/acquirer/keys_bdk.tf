resource "aws_paymentcryptography_key" "bdk-key" {
  exportable = true
  key_attributes {
    key_algorithm = "TDES_2KEY"
    key_class     = "SYMMETRIC_KEY"
    key_usage     = "TR31_B0_BASE_DERIVATION_KEY"
    key_modes_of_use {
      derive_key = true

    }
  }
}

resource "aws_paymentcryptography_key_alias" "bdk-key" {
  alias_name = "alias/bdk-key"
  key_arn    = aws_paymentcryptography_key.bdk-key.arn
}