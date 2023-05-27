package aws.example.magnus;

import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;

import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;

import com.amazonaws.services.magnuscontrolplane.AWSMagnusControlPlane;
import com.amazonaws.services.magnuscontrolplane.AWSMagnusControlPlaneClient;
import com.amazonaws.services.magnuscontrolplane.AWSMagnusControlPlaneClientBuilder;
import com.amazonaws.services.magnuscontrolplane.model.*;

import static aws.example.magnus.Constants.REGION;
import static aws.example.magnus.Constants.CONTROL_ENDPOINT;

public class ControlPlaneUtils {

    public static AWSMagnusControlPlane getControlPlaneClient() {
        return AWSMagnusControlPlaneClientBuilder.standard()
            .withCredentials(new EnvironmentVariableCredentialsProvider())
            .withEndpointConfiguration(new EndpointConfiguration(CONTROL_ENDPOINT, REGION))
            .build();
    }

    public static Alias getOrCreateAlias(String aliasName) {
        return getOrCreateAlias(aliasName, null);
    }

    public static Alias getOrCreateAlias(String aliasName, String keyArn) {
        AWSMagnusControlPlane client = getControlPlaneClient();
        try {
            return client.getAlias(new GetAliasRequest().withAliasName(aliasName)).getAlias();
        } catch (RuntimeException ex) {
            return client.createAlias(new CreateAliasRequest().withAliasName(aliasName).withKeyArn(keyArn)).getAlias();
        }
    }

    public static Alias upsertAlias(String aliasName, String keyArn) {
        AWSMagnusControlPlane client = getControlPlaneClient();
        Alias alias = getOrCreateAlias(aliasName, keyArn);
        if (
            ((null == keyArn) != (null == alias.getKeyArn())) // One is null and the other isn't
            || (null != keyArn && !keyArn.equals(alias.getKeyArn())) // They're both non-null and not the same
            ) {
            return client.updateAlias(new UpdateAliasRequest().withAliasName(aliasName).withKeyArn(keyArn)).getAlias();
        }
        return alias;
    }

    public static Key getKey(String keyArn) {
        AWSMagnusControlPlane client = getControlPlaneClient();
        return client.getKey(new GetKeyRequest().withKeyArn(keyArn)).getKey();
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
            .withExportable(false);
        AWSMagnusControlPlane client = getControlPlaneClient();
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
            .withExportable(false);
        AWSMagnusControlPlane client = getControlPlaneClient();
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
            .withExportable(false);
        AWSMagnusControlPlane client = getControlPlaneClient();
        Key key = client.createKey(request).getKey();
        return key;
    }

    public static GetParametersForImportResult getImportKeyParams() {
        //aws magnus get-parameters-for-import --key-material-type TR34_KEY_BLOCK --wrapping-key-algorithm RSA_2048
        GetParametersForImportRequest request  = new GetParametersForImportRequest();
        request.setWrappingKeyAlgorithm("TR_34");
        request.setWrappingKeyAlgorithm("RSA_2048");
        request.setKeyMaterialType("TR34_KEY_BLOCK");

        AWSMagnusControlPlane client = getControlPlaneClient();
        GetParametersForImportResult result = client.getParametersForImport(request);
        return result;
    }
}
