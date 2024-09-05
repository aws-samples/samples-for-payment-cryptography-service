package aws.sample.paymentcryptography.hmac;

import java.util.concurrent.ExecutionException;
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
public class HMACService {

    public String getHMACKey() throws InterruptedException, ExecutionException {
        Alias hmacKeyAlias = ControlPlaneUtils.getOrCreateAlias(ServiceConstants.HMAC_KEY_ALIAS);

        if (!StringUtils.isBlank(hmacKeyAlias.keyArn())) {
            return hmacKeyAlias.keyArn();
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
        ControlPlaneUtils.upsertAlias(hmacKeyAlias.aliasName(), key.keyArn());
        return hmacKeyAlias.aliasName();
    }

    public String generateMac(String text) throws InterruptedException, ExecutionException {
        String hmacKeyArn = getHMACKey();
        GenerateMacResponse macGenerateResponse = generateMac(hmacKeyArn,text);
        return macGenerateResponse.mac();
    }

    public GenerateMacResponse generateMac(String hmacKeyArn, String text) {
        MacAttributes macAttributes = MacAttributes
                .builder()
                .algorithm(MacAlgorithm.ISO9797_ALGORITHM3)
                .build();

        Logger.getGlobal().info("HMACService:generateMac Attempting to generate HMAC thru AWS Cryptography Service for text " + text);
        GenerateMacRequest generateMacRequest = GenerateMacRequest
                .builder()
                .keyIdentifier(hmacKeyArn)
                .messageData(Hex.encodeHexString(text.getBytes()))
                .generationAttributes(macAttributes)
                .build();

        GenerateMacResponse macGenerateResponse = DataPlaneUtils.getDataPlaneClient().generateMac(generateMacRequest);
        Logger.getGlobal().info("HMACService:generateMac HMAC generation successfult for " + text + ". HMAC is " + macGenerateResponse.mac());
        return macGenerateResponse;
    }

    public VerifyMacResponse getMacVerification(String hmacKeyArn, String mac) {
        MacAttributes macAttributes = MacAttributes
                .builder()
                .algorithm(MacAlgorithm.ISO9797_ALGORITHM3)
                .build();

        VerifyMacRequest verifyMacRequest = VerifyMacRequest
                .builder()
                .keyIdentifier(hmacKeyArn)
                .verificationAttributes(macAttributes)
                .mac(mac)
                .messageData(mac)
                .build();
        VerifyMacResponse macVerificationResponse = DataPlaneUtils.getDataPlaneClient().verifyMac(verifyMacRequest);
        return macVerificationResponse;
    }
}
