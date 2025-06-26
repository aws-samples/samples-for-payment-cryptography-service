package aws.sample.paymentcryptography.mac;

import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Hex;
import org.springframework.stereotype.Component;

import aws.sample.paymentcryptography.ControlPlaneUtils;
import aws.sample.paymentcryptography.DataPlaneUtils;
import aws.sample.paymentcryptography.ServiceConstants;
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

@Component
public class MACService {

    public String getMACKey() throws InterruptedException, ExecutionException {
        Alias iso9797MacKeyAlias = ControlPlaneUtils.getOrCreateAlias(ServiceConstants.ISO_9797_3_MAC_KEY_ALIAS);

        if (!StringUtils.isBlank(iso9797MacKeyAlias.keyArn())) {
            return iso9797MacKeyAlias.keyArn();
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
                
        CreateKeyRequest request = CreateKeyRequest.builder()
        .keyAttributes(attributes)
        .enabled(true)
        .exportable(true)
        .build();

        Key key = ControlPlaneUtils.getControlPlaneClient().createKey(request).key();
        ControlPlaneUtils.upsertAlias(iso9797MacKeyAlias.aliasName(), key.keyArn());
        return iso9797MacKeyAlias.aliasName();
    }

    public String generateMac(String text) throws InterruptedException, ExecutionException {
        String macKeyArn = getMACKey();
        GenerateMacResponse macGenerateResponse = generateMac(macKeyArn,text);
        return macGenerateResponse.mac();
    }

    public GenerateMacResponse generateMac(String macKeyArn, String text) {
        MacAttributes macAttributes = MacAttributes
                .builder()
                .algorithm(MacAlgorithm.ISO9797_ALGORITHM3)
                .build();

        Logger.getGlobal().log(Level.INFO,"MACService:generateMac Attempting to generate MAC thru AWS Cryptography Service for text {0}", text);
        GenerateMacRequest generateMacRequest = GenerateMacRequest
                .builder()
                .keyIdentifier(macKeyArn)
                .messageData(Hex.encodeHexString(text.getBytes()))
                .generationAttributes(macAttributes)
                .build();

        GenerateMacResponse macGenerateResponse = DataPlaneUtils.getDataPlaneClient().generateMac(generateMacRequest);
        Logger.getGlobal().log(Level.INFO,"MACService:generateMac MAC generation successfult for {0}. MAC is {1}", new Object[] {text,macGenerateResponse.mac()});
        return macGenerateResponse;
    }

    public VerifyMacResponse getMacVerification(String macKeyArn, String mac) {
        MacAttributes macAttributes = MacAttributes
                .builder()
                .algorithm(MacAlgorithm.ISO9797_ALGORITHM3)
                .build();

        VerifyMacRequest verifyMacRequest = VerifyMacRequest
                .builder()
                .keyIdentifier(macKeyArn)
                .verificationAttributes(macAttributes)
                .mac(mac)
                .messageData(mac)
                .build();
        VerifyMacResponse macVerificationResponse = DataPlaneUtils.getDataPlaneClient().verifyMac(verifyMacRequest);
        return macVerificationResponse;
    }
}
