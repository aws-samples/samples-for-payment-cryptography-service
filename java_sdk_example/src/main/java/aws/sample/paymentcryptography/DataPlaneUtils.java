package aws.sample.paymentcryptography;

import software.amazon.awssdk.services.paymentcryptography.PaymentCryptographyAsyncClient;
import software.amazon.awssdk.services.paymentcryptographydata.PaymentCryptographyDataAsyncClient;
import software.amazon.awssdk.services.paymentcryptographydata.PaymentCryptographyDataClient;
import software.amazon.awssdk.services.paymentcryptographydata.model.CardGenerationAttributes;
import software.amazon.awssdk.services.paymentcryptographydata.model.DukptDerivationAttributes;
import software.amazon.awssdk.services.paymentcryptographydata.model.GenerateCardValidationDataRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.GenerateCardValidationDataResponse;
import software.amazon.awssdk.services.paymentcryptographydata.model.GeneratePinDataRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.GeneratePinDataResponse;
import software.amazon.awssdk.services.paymentcryptographydata.model.PinGenerationAttributes;
import software.amazon.awssdk.services.paymentcryptographydata.model.TranslatePinDataRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.TranslatePinDataResponse;
import software.amazon.awssdk.services.paymentcryptographydata.model.TranslationIsoFormats;
import software.amazon.awssdk.services.paymentcryptographydata.model.TranslationPinDataIsoFormat034;
import software.amazon.awssdk.services.paymentcryptographydata.model.TranslationPinDataIsoFormat1;
import software.amazon.awssdk.services.paymentcryptographydata.model.VisaPin;

public class DataPlaneUtils {

        private static PaymentCryptographyDataClient dataPlaneClient;
        private static PaymentCryptographyDataAsyncClient asyncClient;

        public static PaymentCryptographyDataClient getDataPlaneClient() {
                if (dataPlaneClient != null) {
                        return dataPlaneClient;
                }
                dataPlaneClient = PaymentCryptographyDataClient.create();
                return dataPlaneClient;
        }

        public static PaymentCryptographyDataAsyncClient getDataPlaneAsyncClient() {
                if (asyncClient != null) {
                        return asyncClient;
                }
                asyncClient = PaymentCryptographyDataAsyncClient.create();
                return asyncClient;
        }

        public static GeneratePinDataResponse generateVisaPinBlock(
                        String pekArn,
                        String pgkArn,
                        String pinBlockFormat,
                        String primaryAccountNumber,
                        int verificationKeyIndex) {
                VisaPin visaPin = VisaPin
                                .builder()
                                .pinVerificationKeyIndex(verificationKeyIndex)
                                .build();
                PinGenerationAttributes attributes = PinGenerationAttributes
                                .builder()
                                .visaPin(visaPin)
                                .build();
                GeneratePinDataRequest request = GeneratePinDataRequest
                                .builder()
                                .generationKeyIdentifier(pgkArn)
                                .encryptionKeyIdentifier(pekArn)
                                .primaryAccountNumber(primaryAccountNumber)
                                .pinBlockFormat(pinBlockFormat)
                                .generationAttributes(attributes)
                                .build();

                PaymentCryptographyDataClient client = getDataPlaneClient();
                GeneratePinDataResponse generatePinDataResponse = client.generatePinData(request);
                return generatePinDataResponse;
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
                DukptDerivationAttributes dupktAttributes = DukptDerivationAttributes.builder()
                                .keySerialNumber(keySerialNumber)
                                .build();

                if (outDukptDerivationType != null) {
                        dupktAttributes = dupktAttributes.toBuilder().dukptKeyDerivationType(outDukptDerivationType).build();
                }
                TranslatePinDataRequest request = TranslatePinDataRequest.builder()
                                .incomingKeyIdentifier(inKeyArn)
                                .outgoingKeyIdentifier(outKeyArn)
                                .incomingTranslationAttributes(inAttributes)
                                .outgoingTranslationAttributes(outAttributes)
                                .outgoingDukptAttributes(dupktAttributes)
                                .encryptedPinBlock(inPinBlock)
                                .build();
                PaymentCryptographyDataClient client = getDataPlaneClient();
                TranslatePinDataResponse translatePinDataResponse = client.translatePinData(request);
                return translatePinDataResponse.pinBlock();
        }

        public static TranslatePinDataResponse translateVisaPinBlockBdkToPek(
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
                DukptDerivationAttributes dupktAttributes = DukptDerivationAttributes
                                .builder()
                                .keySerialNumber(keySerialNumber)
                                .build();

                if (outDukptDerivationType != null) {
                        dupktAttributes
                        .toBuilder()
                        .dukptKeyDerivationType(outDukptDerivationType)
                        .build();
                }

                TranslatePinDataRequest request = TranslatePinDataRequest
                                .builder()
                                .incomingKeyIdentifier(inKeyArn)
                                .incomingTranslationAttributes(inAttributes)
                                .encryptedPinBlock(inPinBlock)
                                .outgoingKeyIdentifier(outKeyArn)
                                .outgoingTranslationAttributes(outAttributes)
                                .incomingDukptAttributes(dupktAttributes)
                                .build();

                PaymentCryptographyDataClient client = getDataPlaneClient();
                TranslatePinDataResponse translatePinDataResponse = client.translatePinData(request);
                // return result.getPinBlock();
                return translatePinDataResponse;
        }

        private static TranslationIsoFormats getIsoFormatAttributes(String isoFormat, String primaryAccountNumber) {
                TranslationIsoFormats isoAttributes = null;
                if ("ISO_FORMAT_1".equals(isoFormat)) {
                        // ISO FORMAT 1
                        isoAttributes = TranslationIsoFormats
                                        .builder()
                                        .isoFormat1(TranslationPinDataIsoFormat1.builder().build())
                                        .build();
                } else if ("ISO_FORMAT_4".equals(isoFormat)) {
                        // ISO FORMAT 4
                        isoAttributes = TranslationIsoFormats
                                        .builder()
                                        .isoFormat4(TranslationPinDataIsoFormat034.builder().primaryAccountNumber(primaryAccountNumber).build())
                                        .build();
                } else if ("ISO_FORMAT_3".equals(isoFormat)) {
                        // ISO FORMAT 3
                        isoAttributes = TranslationIsoFormats
                                        .builder()
                                        .isoFormat3(TranslationPinDataIsoFormat034.builder().primaryAccountNumber(primaryAccountNumber).build())
                                        .build();
                                                
                } else {
                        // ISO FORMAT 0
                        isoAttributes = TranslationIsoFormats
                                        .builder()
                                        .isoFormat0(TranslationPinDataIsoFormat034.builder().primaryAccountNumber(primaryAccountNumber).build())
                                        .build();
                }
                return isoAttributes;
        }

        public static GenerateCardValidationDataResponse generateCardDataValue(CardGenerationAttributes arguments,
                        /* CardDataGenerationType type, */ String keyIdentifier) {
                GenerateCardValidationDataRequest cardDataValidationRequest = GenerateCardValidationDataRequest
                                .builder()
                                .generationAttributes(arguments)
                                // .withCardDataType(type)
                                .keyIdentifier(keyIdentifier)
                                .build();

                PaymentCryptographyDataClient client = getDataPlaneClient();
                GenerateCardValidationDataResponse generateCardValidationDataResponse = client.generateCardValidationData(cardDataValidationRequest);
                return generateCardValidationDataResponse;
        }

}
