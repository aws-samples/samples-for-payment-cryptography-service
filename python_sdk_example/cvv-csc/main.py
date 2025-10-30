import boto3
TAG_KEY = "SAMPLE-CVV-CSC"
PAN="343412341234123"
EXP_DATE="0930"
controlplane_client = boto3.client("payment-cryptography")
dataplane_client = boto3.client("payment-cryptography-data")

def validate_mastercard_visa_cvv2(key, pan, expiryDate, cvv):
    try:
        response = dataplane_client.verify_card_validation_data(
            KeyIdentifier=key,
            PrimaryAccountNumber=pan,
            VerificationAttributes={"CardVerificationValue2" : {"CardExpiryDate":expiryDate}},
            ValidationData=cvv
            )
        # if response HTTP code is 200 it means it was validated, otherwise (HTTP != 200) boto3 raises an exception.
        print("CVV %s is correct" % cvv)
    except:
        print("CVV %s is wrong" % cvv)


def validate_amex_cvv2(key, pan, expiryDate, cvv):
    try:
        response = dataplane_client.verify_card_validation_data(
            KeyIdentifier=key,
            PrimaryAccountNumber=pan,
            VerificationAttributes={"AmexCardSecurityCodeVersion2" : {"CardExpiryDate":expiryDate, "ServiceCode":"000"}},
            ValidationData=cvv
            )
        print("CVV %s is correct" % cvv)
    except:
        print("CVV %s is wrong" % cvv)





if __name__ == "__main__":
    key_arn = controlplane_client.create_key(Exportable=True,
                                                     KeyAttributes={
                                                         "KeyAlgorithm": "TDES_2KEY",
                                                         "KeyUsage": "TR31_C0_CARD_VERIFICATION_KEY",
                                                         "KeyClass": "SYMMETRIC_KEY",
                                                         "KeyModesOfUse": {"Generate": True, "Verify": True}
                                                     },
                                                     Tags=[{"Key": TAG_KEY, "Value": "1"}])['Key']['KeyArn']


    print("Generating VISA/MASTERCARD CVV2")
    # Generate Visa/Mastercard CVV2
    mc_response = dataplane_client.generate_card_validation_data(
        KeyIdentifier=key_arn,
        PrimaryAccountNumber=PAN,
        GenerationAttributes={"CardVerificationValue2" : {"CardExpiryDate":EXP_DATE}}
        )

    mc_cvv2 = mc_response["ValidationData"]
    print("Generated CVV2 %s" % mc_cvv2)
    # Validate Incoming Visa/Mastercard CVV2
    print("Validating VISA/MASTERCARD CVV2")
    validate_mastercard_visa_cvv2(key_arn, PAN, EXP_DATE, mc_cvv2)

    # Generate AMEX CVV2
    print("Generating AMEX CVV2")
    amex_response = dataplane_client.generate_card_validation_data(
        KeyIdentifier=key_arn,
        PrimaryAccountNumber=PAN,
        GenerationAttributes={"AmexCardSecurityCodeVersion2" : {"CardExpiryDate":EXP_DATE, "ServiceCode":"999"}},
        ValidationDataLength=4
        )


    amex_cvv2 = amex_response["ValidationData"]
    print("Generated CVV2 %s" % amex_cvv2)
    # Validate Incoming AMEX CVV2
    print("Validating AMEX CVV2")
    validate_amex_cvv2(key_arn, PAN, EXP_DATE, amex_cvv2)


