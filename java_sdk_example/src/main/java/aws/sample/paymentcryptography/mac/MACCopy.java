package aws.sample.paymentcryptography.mac;

import java.util.concurrent.ExecutionException;
import java.util.logging.Logger;

import aws.sample.paymentcryptography.ControlPlaneUtils;
import aws.sample.paymentcryptography.DataPlaneUtils;
import software.amazon.awssdk.services.paymentcryptography.model.Alias;
import software.amazon.awssdk.services.paymentcryptography.model.CreateKeyRequest;
import software.amazon.awssdk.services.paymentcryptography.model.Key;
import software.amazon.awssdk.services.paymentcryptography.model.KeyAlgorithm;
import software.amazon.awssdk.services.paymentcryptography.model.KeyAttributes;
import software.amazon.awssdk.services.paymentcryptography.model.KeyClass;
import software.amazon.awssdk.services.paymentcryptography.model.KeyModesOfUse;
import software.amazon.awssdk.services.paymentcryptography.model.KeyUsage;
import software.amazon.awssdk.services.paymentcryptographydata.model.GenerateMacRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.GenerateMacResponse;
import software.amazon.awssdk.services.paymentcryptographydata.model.MacAlgorithm;
import software.amazon.awssdk.services.paymentcryptographydata.model.MacAttributes;
import software.amazon.awssdk.services.paymentcryptographydata.model.VerifyMacRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.VerifyMacResponse;
import software.amazon.awssdk.utils.StringUtils;

public class MACCopy {

    private static final String MESSAGE = "4123412341234123";
    private static final String MAC_KEY_ALIAS = "alias/tr34-mac-key-import";

    public static void main(String[] args) throws InterruptedException, ExecutionException {

        String macKeyArn = createMACKey();

        GenerateMacResponse macGenerateResponse = generateMac(macKeyArn);
        Logger.getGlobal().info("MAC Key Check Value - " + macGenerateResponse.keyCheckValue() + "\t MAC - "
                + macGenerateResponse.mac());

        VerifyMacResponse macVerificatioResponse = getMacVerification(macKeyArn, macGenerateResponse.mac());
        Logger.getGlobal().info("MAC Verification Key Check Value - " + macVerificatioResponse.keyCheckValue());

        Logger.getGlobal().info(
                "Mac Verified = " + (macGenerateResponse.keyCheckValue().equals(macVerificatioResponse.keyCheckValue())));
    }

    public static String createMACKey() throws InterruptedException, ExecutionException {
        Alias macKeyAlias = ControlPlaneUtils.getOrCreateAlias(MAC_KEY_ALIAS);

        if (!StringUtils.isBlank(macKeyAlias.keyArn())) {
            return macKeyAlias.keyArn();
        }

        KeyModesOfUse modes = KeyModesOfUse
                .builder()
                .generate(true)
                .verify(true)
                .build();

        KeyAttributes attributes = KeyAttributes
                .builder()
                .keyAlgorithm(KeyAlgorithm.TDES_2_KEY)
                .keyClass(KeyClass.SYMMETRIC_KEY)
                .keyUsage(KeyUsage.TR31_M3_ISO_9797_3_MAC_KEY)
                .keyModesOfUse(modes)
                .build();

        CreateKeyRequest request = CreateKeyRequest
                .builder()
                .keyAttributes(attributes)
                .enabled(true)
                .exportable(false)
                .build();

        Key key = ControlPlaneUtils.getControlPlaneClient().createKey(request).key();
        ControlPlaneUtils.upsertAlias(macKeyAlias.aliasName(), key.keyArn());
        return macKeyAlias.aliasName();
    }

    public static String generateMac() throws InterruptedException, ExecutionException {
        String macKeyArn = createMACKey();
        GenerateMacResponse macGenerateResponse = generateMac(macKeyArn);
        return macGenerateResponse.mac();
    }

    public static GenerateMacResponse generateMac(String macKeyArn) {
        MacAttributes macAttributes = MacAttributes
                .builder()
                .algorithm(MacAlgorithm.ISO9797_ALGORITHM3)
                .build();

        GenerateMacRequest generateMacRequest = GenerateMacRequest
                .builder()
                .keyIdentifier(macKeyArn)
                .messageData(MESSAGE)
                .generationAttributes(macAttributes)
                .build();

        GenerateMacResponse macGenerateResponse = DataPlaneUtils.getDataPlaneClient().generateMac(generateMacRequest);
        return macGenerateResponse;
    }

    public static VerifyMacResponse getMacVerification(String macKeyArn, String mac) {
        MacAttributes macAttributes = MacAttributes
                .builder()
                .algorithm(MacAlgorithm.ISO9797_ALGORITHM3)
                .build();
                
        VerifyMacRequest verifyMacRequest = VerifyMacRequest
                .builder()
                .keyIdentifier(macKeyArn)
                .verificationAttributes(macAttributes)
                .mac(mac)
                .messageData(MESSAGE)
                .build();
        VerifyMacResponse macVerificationResponse = DataPlaneUtils.getDataPlaneClient().verifyMac(verifyMacRequest);
        return macVerificationResponse;
    }
}
