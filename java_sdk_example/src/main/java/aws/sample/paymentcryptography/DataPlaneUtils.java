package aws.sample.paymentcryptography;

import static aws.sample.paymentcryptography.Constants.DATA_ENDPOINT;
import static aws.sample.paymentcryptography.Constants.REGION;

import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;
import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;
import com.amazonaws.services.paymentcryptographydata.AWSPaymentCryptographyData;
import com.amazonaws.services.paymentcryptographydata.AWSPaymentCryptographyDataClientBuilder;
import com.amazonaws.services.paymentcryptographydata.model.CardGenerationAttributes;
import com.amazonaws.services.paymentcryptographydata.model.CardVerificationAttributes;
import com.amazonaws.services.paymentcryptographydata.model.DukptDerivationAttributes;
import com.amazonaws.services.paymentcryptographydata.model.GenerateCardValidationDataRequest;
import com.amazonaws.services.paymentcryptographydata.model.GenerateCardValidationDataResult;
import com.amazonaws.services.paymentcryptographydata.model.GeneratePinDataRequest;
import com.amazonaws.services.paymentcryptographydata.model.GeneratePinDataResult;
import com.amazonaws.services.paymentcryptographydata.model.PinGenerationAttributes;
import com.amazonaws.services.paymentcryptographydata.model.TranslatePinDataRequest;
import com.amazonaws.services.paymentcryptographydata.model.TranslatePinDataResult;
import com.amazonaws.services.paymentcryptographydata.model.TranslationIsoFormats;
import com.amazonaws.services.paymentcryptographydata.model.TranslationPinDataIsoFormat034;
import com.amazonaws.services.paymentcryptographydata.model.TranslationPinDataIsoFormat1;
import com.amazonaws.services.paymentcryptographydata.model.VerifyCardValidationDataRequest;
import com.amazonaws.services.paymentcryptographydata.model.VerifyCardValidationDataResult;
import com.amazonaws.services.paymentcryptographydata.model.VisaPin;

public class DataPlaneUtils {

        private static AWSPaymentCryptographyData dataPlaneClient;

        public static AWSPaymentCryptographyData getDataPlaneClient() {
                if (dataPlaneClient != null) {
                        return dataPlaneClient;
                }

                dataPlaneClient = AWSPaymentCryptographyDataClientBuilder
                                .standard()
                                .withCredentials(new EnvironmentVariableCredentialsProvider())
                                .withEndpointConfiguration(new EndpointConfiguration(DATA_ENDPOINT, REGION))
                                .build();

                return dataPlaneClient;
        }

        public static String generateVisaPinBlock(
                        String pekArn,
                        String pgkArn,
                        String pinBlockFormat,
                        String primaryAccountNumber,
                        int verificationKeyIndex) {
                VisaPin visaPin = new VisaPin()
                                .withPinVerificationKeyIndex(verificationKeyIndex);
                PinGenerationAttributes attributes = new PinGenerationAttributes()
                                .withVisaPin(visaPin);
                GeneratePinDataRequest request = new GeneratePinDataRequest()
                                .withGenerationKeyIdentifier(pgkArn)
                                .withEncryptionKeyIdentifier(pekArn)
                                .withPrimaryAccountNumber(primaryAccountNumber)
                                .withPinBlockFormat(pinBlockFormat)
                                .withGenerationAttributes(attributes);

                AWSPaymentCryptographyData client = getDataPlaneClient();
                GeneratePinDataResult result = client.generatePinData(request);
                return result.getEncryptedPinBlock();
        }

        public static String translateVisaPinBlockPekToBdk(
                        String inKeyArn,
                        String inPinBlockFormat,
                        String inPinBlock,
                        String outKeyArn,
                        String outPinBlockFormat,
                        String outDukptDerivationType,
                        String keySerialNumber,
                        String primaryAccountNumber) {
                TranslationIsoFormats inAttributes = getIsoFormatAttributes(inPinBlockFormat, primaryAccountNumber);
                TranslationIsoFormats outAttributes = getIsoFormatAttributes(outPinBlockFormat, primaryAccountNumber);
                DukptDerivationAttributes dupktAttributes = new DukptDerivationAttributes()
                                .withKeySerialNumber(keySerialNumber);

                if (outDukptDerivationType != null) {
                        dupktAttributes.setDukptKeyDerivationType(outDukptDerivationType);
                }
                TranslatePinDataRequest request = new TranslatePinDataRequest()
                                .withIncomingKeyIdentifier(inKeyArn)
                                .withOutgoingKeyIdentifier(outKeyArn)
                                .withIncomingTranslationAttributes(inAttributes)
                                .withOutgoingTranslationAttributes(outAttributes)
                                .withOutgoingDukptAttributes(dupktAttributes)
                                .withEncryptedPinBlock(inPinBlock);
                AWSPaymentCryptographyData client = getDataPlaneClient();
                TranslatePinDataResult result = client.translatePinData(request);
                return result.getPinBlock();
        }

        public static String translateVisaPinBlockBdkToPek(
                        String inKeyArn,
                        String inPinBlockFormat,
                        String inPinBlock,
                        String outKeyArn,
                        String outPinBlockFormat,
                        String outDukptDerivationType,
                        String keySerialNumber,
                        String primaryAccountNumber) {
                TranslationIsoFormats inAttributes = getIsoFormatAttributes(inPinBlockFormat, primaryAccountNumber);
                TranslationIsoFormats outAttributes = getIsoFormatAttributes(outPinBlockFormat, primaryAccountNumber);
                DukptDerivationAttributes dupktAttributes = new DukptDerivationAttributes()
                                .withKeySerialNumber(keySerialNumber);

                /*
                 * if (outDukptDerivationType != null) {
                 * dupktAttributes.setDukptKeyDerivationType(outDukptDerivationType);
                 * }
                 */
                TranslatePinDataRequest request = new TranslatePinDataRequest()
                                .withIncomingKeyIdentifier(inKeyArn)
                                .withOutgoingKeyIdentifier(outKeyArn)
                                .withIncomingTranslationAttributes(inAttributes)
                                .withOutgoingTranslationAttributes(outAttributes)
                                .withIncomingDukptAttributes(dupktAttributes)
                                .withEncryptedPinBlock(inPinBlock);
                AWSPaymentCryptographyData client = getDataPlaneClient();
                TranslatePinDataResult result = client.translatePinData(request);
                return result.getPinBlock();
        }

        private static TranslationIsoFormats getIsoFormatAttributes(String isoFormat, String primaryAccountNumber) {
                TranslationIsoFormats isoAttributes = null;
                if ("ISO_FORMAT_1".equals(isoFormat)) {
                        // ISO FORMAT 1
                        isoAttributes = new TranslationIsoFormats()
                                        .withIsoFormat1(new TranslationPinDataIsoFormat1());
                } else if ("ISO_FORMAT_4".equals(isoFormat)) {
                        // ISO FORMAT 4
                        isoAttributes = new TranslationIsoFormats()
                                        .withIsoFormat4(
                                                        new TranslationPinDataIsoFormat034()
                                                                        .withPrimaryAccountNumber(
                                                                                        primaryAccountNumber));
                } else if ("ISO_FORMAT_3".equals(isoFormat)) {
                        // ISO FORMAT 3
                        isoAttributes = new TranslationIsoFormats()
                                        .withIsoFormat3(
                                                        new TranslationPinDataIsoFormat034()
                                                                        .withPrimaryAccountNumber(
                                                                                        primaryAccountNumber));
                } else {
                        // ISO FORMAT 0
                        isoAttributes = new TranslationIsoFormats()
                                        .withIsoFormat0(
                                                        new TranslationPinDataIsoFormat034()
                                                                        .withPrimaryAccountNumber(
                                                                                        primaryAccountNumber));
                }
                return isoAttributes;
        }

        public static GenerateCardValidationDataResult generateCardDataValue(CardGenerationAttributes arguments,
                        /* CardDataGenerationType type, */ String keyIdentifier) {
                GenerateCardValidationDataRequest cardDataValidationRequest = new GenerateCardValidationDataRequest()
                                .withGenerationAttributes(arguments)
                                // .withCardDataType(type)
                                .withKeyIdentifier(keyIdentifier);

                AWSPaymentCryptographyData client = getDataPlaneClient();
                GenerateCardValidationDataResult result = client.generateCardValidationData(cardDataValidationRequest);
                return result;
        }

        /*
         * public static GenerateCardDataResult generateCardDataValue(CardDataArguments
         * arguments, CardDataGenerationType type, String keyIdentifier){
         * GenerateCardDa cardDataRequest = new GenerateCardDataRequest()
         * .withCardDataGenerationArguments(arguments)
         * .withCardDataType(type)
         * .withCardDataGenerationKeyIdentifier(keyIdentifier);
         * 
         * AWSPaymentCryptographyData client = getDataPlaneClient();
         * GenerateCardDataResult result = client.generateCardData(cardDataRequest);
         * return result;
         * }
         */

        /*
         * public static VerifyCardDataResult verifyCardDataValue(CardDataArguments
         * cardDataArguments, String cardDataValue, String
         * cardDataVerificationKeyIdentifier) {
         * VerifyCardDataRequest verifyCardDataRequest = new VerifyCardDataRequest()
         * .withCardDataType(CardDataVerificationType.CARD_VERIFICATION_VALUE_2)
         * .withCardDataValue(cardDataValue)
         * .withCardDataVerificationKeyIdentifier(cardDataVerificationKeyIdentifier)
         * .withCardDataVerificationArguments(cardDataArguments);
         * 
         * AWSMagnusDataPlane client = getDataPlaneClient();
         * VerifyCardDataResult result = client.verifyCardData(verifyCardDataRequest);
         * return result;
         * 
         * }
         */

        public static VerifyCardValidationDataResult verifyCardDataValue(
                        CardVerificationAttributes cardVerificationAttributes, String cardDataValue,
                        String cardDataVerificationKeyIdentifier) {
                VerifyCardValidationDataRequest verifyCardValidationDataRequest = new VerifyCardValidationDataRequest()
                                .withVerificationAttributes(cardVerificationAttributes)
                                // .withCardDataType(CardDataVerificationType.CARD_VERIFICATION_VALUE_2)
                                .withKeyIdentifier(cardDataVerificationKeyIdentifier);
                // .withCardVerificationAttributes(cardVerificationAttributes);

                AWSPaymentCryptographyData client = getDataPlaneClient();
                VerifyCardValidationDataResult result = client
                                .verifyCardValidationData(verifyCardValidationDataRequest);
                return result;

        }
}
