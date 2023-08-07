package aws.sample.paymentcryptography;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.paymentcryptographydata.AWSPaymentCryptographyData;
import com.amazonaws.services.paymentcryptographydata.AWSPaymentCryptographyDataClientBuilder;
import com.amazonaws.services.paymentcryptographydata.model.CardGenerationAttributes;
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
import com.amazonaws.services.paymentcryptographydata.model.VisaPin;

public class DataPlaneUtils {

        private static AWSPaymentCryptographyData dataPlaneClient;

        public static AWSPaymentCryptographyData getDataPlaneClient() {
                if (dataPlaneClient != null) {
                        return dataPlaneClient;
                }

                dataPlaneClient = AWSPaymentCryptographyDataClientBuilder
                                .standard()
                                .withRegion(Regions.US_EAST_1)
                                .build();

                return dataPlaneClient;
        }

        public static GeneratePinDataResult generateVisaPinBlock(
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
                return result;
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

        public static TranslatePinDataResult translateVisaPinBlockBdkToPek(
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
                                .withIncomingTranslationAttributes(inAttributes)
                                .withEncryptedPinBlock(inPinBlock)
                                .withOutgoingKeyIdentifier(outKeyArn)
                                .withOutgoingTranslationAttributes(outAttributes)
                                .withIncomingDukptAttributes(dupktAttributes);

                AWSPaymentCryptographyData client = getDataPlaneClient();
                TranslatePinDataResult result = client.translatePinData(request);
                // return result.getPinBlock();
                return result;
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

}
