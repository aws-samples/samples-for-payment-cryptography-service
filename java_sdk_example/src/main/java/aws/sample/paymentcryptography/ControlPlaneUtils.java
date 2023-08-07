package aws.sample.paymentcryptography;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.paymentcryptography.AWSPaymentCryptographyAsync;
import com.amazonaws.services.paymentcryptography.AWSPaymentCryptographyAsyncClientBuilder;
import com.amazonaws.services.paymentcryptography.model.Alias;
import com.amazonaws.services.paymentcryptography.model.CreateAliasRequest;
import com.amazonaws.services.paymentcryptography.model.CreateKeyRequest;
import com.amazonaws.services.paymentcryptography.model.GetAliasRequest;
import com.amazonaws.services.paymentcryptography.model.GetKeyRequest;
import com.amazonaws.services.paymentcryptography.model.Key;
import com.amazonaws.services.paymentcryptography.model.KeyAttributes;
import com.amazonaws.services.paymentcryptography.model.KeyModesOfUse;
import com.amazonaws.services.paymentcryptography.model.UpdateAliasRequest;

public class ControlPlaneUtils {

    private static AWSPaymentCryptographyAsync controlPlaneClient = null;

    public static AWSPaymentCryptographyAsync getControlPlaneClient() {
        if (controlPlaneClient != null) {
            return controlPlaneClient;

        }
        controlPlaneClient = AWSPaymentCryptographyAsyncClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        return controlPlaneClient;
    }

    public static Alias getOrCreateAlias(String aliasName) {
        return getOrCreateAlias(aliasName, null);
    }

    public static Alias getOrCreateAlias(String aliasName, String keyArn) {
        AWSPaymentCryptographyAsync client = getControlPlaneClient();
        try {
            return client.getAlias(new GetAliasRequest().withAliasName(aliasName)).getAlias();
        } catch (RuntimeException ex) {
            return client.createAlias(new CreateAliasRequest().withAliasName(aliasName).withKeyArn(keyArn)).getAlias();
        }
    }

    public static Alias upsertAlias(String aliasName, String keyArn) {
        AWSPaymentCryptographyAsync client = getControlPlaneClient();
        Alias alias = getOrCreateAlias(aliasName, keyArn);
        if (((null == keyArn) != (null == alias.getKeyArn())) // One is null and the other isn't
                || (null != keyArn && !keyArn.equals(alias.getKeyArn())) // They're both non-null and not the same
        ) {
            return client.updateAlias(new UpdateAliasRequest().withAliasName(aliasName).withKeyArn(keyArn)).getAlias();
        }
        return alias;
    }

    public static Key getKey(String keyArn) {
        AWSPaymentCryptographyAsync client = getControlPlaneClient();
        return client.getKey(new GetKeyRequest().withKeyIdentifier(keyArn)).getKey();
    }

    public static Key createBDK(String keyAlgorithm) {
        KeyModesOfUse modes = new KeyModesOfUse()
                .withDeriveKey(true);
        KeyAttributes attributes = new KeyAttributes()
                .withKeyAlgorithm(keyAlgorithm)
                .withKeyClass("SYMMETRIC_KEY")
                .withKeyUsage("TR31_B0_BASE_DERIVATION_KEY")
                .withKeyModesOfUse(modes);
        CreateKeyRequest request = new CreateKeyRequest()
                .withKeyAttributes(attributes)
                .withEnabled(true)
                .withExportable(true);
        AWSPaymentCryptographyAsync client = getControlPlaneClient();
        Key key = client.createKey(request).getKey();
        return key;
    }

    public static Key createPEK(String keyAlgorithm) {
        KeyModesOfUse modes = new KeyModesOfUse()
                .withWrap(true)
                .withEncrypt(true)
                .withUnwrap(true)
                .withDecrypt(true);
        KeyAttributes attributes = new KeyAttributes()
                .withKeyAlgorithm(keyAlgorithm)
                .withKeyClass("SYMMETRIC_KEY")
                .withKeyUsage("TR31_P0_PIN_ENCRYPTION_KEY")
                .withKeyModesOfUse(modes);
        CreateKeyRequest request = new CreateKeyRequest()
                .withKeyAttributes(attributes)
                .withEnabled(true)
                .withExportable(true);
        AWSPaymentCryptographyAsync client = getControlPlaneClient();
        Key key = client.createKey(request).getKey();
        return key;
    }

    public static Key createVisaPGK(String keyAlgorithm) {
        KeyModesOfUse modes = new KeyModesOfUse()
                .withGenerate(true)
                .withVerify(true);
        KeyAttributes attributes = new KeyAttributes()
                .withKeyAlgorithm(keyAlgorithm)
                .withKeyClass("SYMMETRIC_KEY")
                .withKeyUsage("TR31_V2_VISA_PIN_VERIFICATION_KEY")
                .withKeyModesOfUse(modes);
        CreateKeyRequest request = new CreateKeyRequest()
                .withKeyAttributes(attributes)
                .withEnabled(true)
                .withExportable(true);
        AWSPaymentCryptographyAsync client = getControlPlaneClient();
        Key key = client.createKey(request).getKey();
        return key;
    }

    public static Key createCVVKey(String keyAlgorithm) {
        KeyModesOfUse modes = new KeyModesOfUse()
                .withGenerate(true)
                .withVerify(true);
        KeyAttributes attributes = new KeyAttributes()
                .withKeyAlgorithm(keyAlgorithm)
                .withKeyClass("SYMMETRIC_KEY")
                .withKeyUsage("TR31_C0_CARD_VERIFICATION_KEY")
                .withKeyModesOfUse(modes);
        CreateKeyRequest request = new CreateKeyRequest()
                .withKeyAttributes(attributes)
                .withEnabled(true)
                .withExportable(true);
        AWSPaymentCryptographyAsync client = getControlPlaneClient();
        Key key = client.createKey(request).getKey();
        return key;
    }
}
