resource "aws_paymentcryptography_key" "cvk-key" {
  exportable = true
  key_attributes {
    key_algorithm = "TDES_2KEY"
    key_class     = "SYMMETRIC_KEY"
    key_usage     = "TR31_C0_CARD_VERIFICATION_KEY"
    key_modes_of_use {
      generate = true
      verify   = true

    }
  }
}

resource "aws_paymentcryptography_key_alias" "cvk-key" {
  alias_name = "alias/cvk-key"
  key_arn    = aws_paymentcryptography_key.cvk-key.arn
}