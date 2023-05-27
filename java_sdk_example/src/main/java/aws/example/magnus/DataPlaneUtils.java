package aws.example.magnus;

import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;

import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;

import com.amazonaws.services.magnusdataplane.AWSMagnusDataPlane;
import com.amazonaws.services.magnusdataplane.AWSMagnusDataPlaneClient;
import com.amazonaws.services.magnusdataplane.AWSMagnusDataPlaneClientBuilder;
import com.amazonaws.services.magnusdataplane.model.PinGenerationAttributes;
import com.amazonaws.services.magnusdataplane.model.DukptDerivationAttributes;
import com.amazonaws.services.magnusdataplane.model.GeneratePinDataRequest;
import com.amazonaws.services.magnusdataplane.model.GeneratePinDataResult;
import com.amazonaws.services.magnusdataplane.model.TranslatePinDataRequest;
import com.amazonaws.services.magnusdataplane.model.TranslatePinDataResult;
import com.amazonaws.services.magnusdataplane.model.TranslationIsoFormats;
import com.amazonaws.services.magnusdataplane.model.TranslationPinDataIsoFormat034;
import com.amazonaws.services.magnusdataplane.model.TranslationPinDataIsoFormat1;
import com.amazonaws.services.magnusdataplane.model.VisaPin;

import static aws.example.magnus.Constants.REGION;
import static aws.example.magnus.Constants.DATA_ENDPOINT;

public class DataPlaneUtils {

    public static AWSMagnusDataPlane getDataPlaneClient() {
        return AWSMagnusDataPlaneClientBuilder.standard()
                .withCredentials(new EnvironmentVariableCredentialsProvider())
                .withEndpointConfiguration(new EndpointConfiguration(DATA_ENDPOINT, REGION))
                .build();
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

        AWSMagnusDataPlane client = getDataPlaneClient();
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
        AWSMagnusDataPlane client = getDataPlaneClient();
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
                                    .withPrimaryAccountNumber(primaryAccountNumber));
        } else if ("ISO_FORMAT_3".equals(isoFormat)) {
            // ISO FORMAT 3
            isoAttributes = new TranslationIsoFormats()
                    .withIsoFormat3(
                            new TranslationPinDataIsoFormat034()
                                    .withPrimaryAccountNumber(primaryAccountNumber));
        } else {
            // ISO FORMAT 0
            isoAttributes = new TranslationIsoFormats()
                    .withIsoFormat0(
                            new TranslationPinDataIsoFormat034()
                                    .withPrimaryAccountNumber(primaryAccountNumber));
        }
        return isoAttributes;
    }
}
