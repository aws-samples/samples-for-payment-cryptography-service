resource "aws_paymentcryptography_key" "pvk-key" {
  exportable = true
  key_attributes {
    key_algorithm = "TDES_2KEY"
    key_class     = "SYMMETRIC_KEY"
    key_usage     = "TR31_V2_VISA_PIN_VERIFICATION_KEY"
    key_modes_of_use {
      generate = true
      verify   = true

    }
  }
}

resource "aws_paymentcryptography_key_alias" "pvk-key" {
  alias_name = "alias/pvk-key"
  key_arn    = aws_paymentcryptography_key.pvk-key.arn
}

resource "aws_paymentcryptography_key" "pek-key" {
  exportable = true
  key_attributes {
    key_algorithm = "TDES_3KEY"
    key_class     = "SYMMETRIC_KEY"
    key_usage     = "TR31_P0_PIN_ENCRYPTION_KEY"
    key_modes_of_use {
      encrypt = true
      decrypt   = true
      wrap = true
      unwrap = true

    }
  }
}

resource "aws_paymentcryptography_key_alias" "pek-key" {
  alias_name = "alias/pek-key"
  key_arn    = aws_paymentcryptography_key.pek-key.arn
}

resource "aws_paymentcryptography_key" "pek-iwk-key" {
  exportable = true
  key_attributes {
    key_algorithm = "TDES_3KEY"
    key_class     = "SYMMETRIC_KEY"
    key_usage     = "TR31_P0_PIN_ENCRYPTION_KEY"
    key_modes_of_use {
      encrypt = true
      decrypt   = true
      wrap = true
      unwrap = true

    }
  }
}

resource "aws_paymentcryptography_key_alias" "pek-iwk-key" {
  alias_name = "alias/pek-iwk-key"
  key_arn    = aws_paymentcryptography_key.pek-iwk-key.arn
}