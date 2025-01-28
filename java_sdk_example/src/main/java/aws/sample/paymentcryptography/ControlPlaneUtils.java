package aws.sample.paymentcryptography;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.logging.Logger;

import software.amazon.awssdk.services.paymentcryptography.PaymentCryptographyAsyncClient;
import software.amazon.awssdk.services.paymentcryptography.PaymentCryptographyClient;
import software.amazon.awssdk.services.paymentcryptography.model.Alias;
import software.amazon.awssdk.services.paymentcryptography.model.CreateAliasRequest;
import software.amazon.awssdk.services.paymentcryptography.model.CreateKeyRequest;
import software.amazon.awssdk.services.paymentcryptography.model.GetAliasRequest;
import software.amazon.awssdk.services.paymentcryptography.model.GetAliasResponse;
import software.amazon.awssdk.services.paymentcryptography.model.GetKeyRequest;
import software.amazon.awssdk.services.paymentcryptography.model.Key;
import software.amazon.awssdk.services.paymentcryptography.model.KeyAttributes;
import software.amazon.awssdk.services.paymentcryptography.model.KeyModesOfUse;
import software.amazon.awssdk.services.paymentcryptography.model.UpdateAliasRequest;
import software.amazon.awssdk.services.paymentcryptography.model.UpdateAliasResponse;
public class ControlPlaneUtils {

    private static PaymentCryptographyClient controlPlaneClient = null;
    private static PaymentCryptographyAsyncClient controlPlaneAsyncClient = null;
    
    public static PaymentCryptographyClient  getControlPlaneClient() {
        if (controlPlaneClient != null) {
            return controlPlaneClient;

        }
        controlPlaneClient =  PaymentCryptographyClient.create();
        return controlPlaneClient;
    }

    public static PaymentCryptographyAsyncClient  getControlPlaneAsyncClient() {
        if (controlPlaneAsyncClient != null) {
            return controlPlaneAsyncClient;

        }
        controlPlaneAsyncClient =  PaymentCryptographyAsyncClient.create();
        return controlPlaneAsyncClient;
    }

    public static Alias getOrCreateAlias(String aliasName) throws InterruptedException, ExecutionException {
        return getOrCreateAlias(aliasName, null);
    }

    public static Alias getOrCreateAlias(String aliasName, String keyArn) throws InterruptedException, ExecutionException {
        PaymentCryptographyClient client = getControlPlaneClient();
        try {
            GetAliasResponse response = client.getAlias(GetAliasRequest.builder().aliasName(aliasName).build());
            return response.alias();
        } catch (RuntimeException ex) {
            CreateAliasRequest request = CreateAliasRequest.builder().aliasName(aliasName).keyArn(keyArn).build();
            return client.createAlias(request).alias();
        }
    }

    public static Alias getOrCreateAliasAsync(String aliasName, String keyArn) throws InterruptedException, ExecutionException {
        PaymentCryptographyAsyncClient client = getControlPlaneAsyncClient();
        try {
            CompletableFuture<GetAliasResponse> response = client.getAlias(
                GetAliasRequest.builder()
                    .aliasName(aliasName)
                    .build()
            );
            
            return response
                .thenCompose(aliasResponse -> {
                    Logger.getGlobal().info("alias " + aliasName + " exists.");
                    // If alias exists, return it
                    return CompletableFuture.completedFuture(aliasResponse.alias());
                })
                .exceptionally(throwable -> {
                    // If alias doesn't exist, create it
                    CreateAliasRequest request = CreateAliasRequest.builder()
                        .aliasName(aliasName)
                        .keyArn(keyArn)
                        .build();
                        
                    return client.createAlias(request)
                        .thenApply(createResponse -> createResponse.alias())
                        .join();
                })
                .get();
        } catch (Exception e) {
            throw new RuntimeException("Failed to get or create alias: " + aliasName, e);
        }
    }

    public static Alias upsertAlias(String aliasName, String keyArn) throws InterruptedException, ExecutionException {
        PaymentCryptographyClient client = getControlPlaneClient();
        Alias alias = getOrCreateAlias(aliasName, keyArn);
        if (((null == keyArn) != (null == alias.keyArn())) // One is null and the other isn't
                || (null != keyArn && !keyArn.equals(alias.keyArn())) // They're both non-null and not the same
        ) {
            UpdateAliasResponse response = client.updateAlias(UpdateAliasRequest.builder().aliasName(aliasName).keyArn(keyArn).build());
            return response.alias();
        }
        return null;
    }

    public static Key getKey(String keyArn) throws InterruptedException, ExecutionException {
        PaymentCryptographyClient client = getControlPlaneClient();
        return client.getKey(GetKeyRequest.builder().keyIdentifier(keyArn).build()).key();
    }

    public static Key createBDK(String keyAlgorithm) throws InterruptedException, ExecutionException {
        KeyModesOfUse modes = KeyModesOfUse.builder()
                .deriveKey(true).build();
        KeyAttributes attributes = KeyAttributes.builder()
                .keyAlgorithm(keyAlgorithm)
                .keyClass("SYMMETRIC_KEY")
                .keyUsage("TR31_B0_BASE_DERIVATION_KEY")
                .keyModesOfUse(modes)
                .build();
        CreateKeyRequest request = CreateKeyRequest.builder()
                .keyAttributes(attributes)
                .enabled(true)
                .exportable(true)
                .build();
        PaymentCryptographyClient client = getControlPlaneClient();
        Key key = client.createKey(request).key();
        return key;
    }

    public static Key createPEK(String keyAlgorithm) throws InterruptedException, ExecutionException {
        KeyModesOfUse modes = KeyModesOfUse.builder()
                .wrap(true)
                .encrypt(true)
                .unwrap(true)
                .decrypt(true)
                .build();
        KeyAttributes attributes = KeyAttributes.builder()
                .keyAlgorithm(keyAlgorithm)
                .keyClass("SYMMETRIC_KEY")
                .keyUsage("TR31_P0_PIN_ENCRYPTION_KEY")
                .keyModesOfUse(modes)
                .build();
        CreateKeyRequest request = CreateKeyRequest.builder()
                .keyAttributes(attributes)
                .enabled(true)
                .exportable(true)
                .build();
        PaymentCryptographyClient client = getControlPlaneClient();
        Key key = client.createKey(request).key();
        return key;
    }

    public static Key createVisaPGK(String keyAlgorithm) throws InterruptedException, ExecutionException {
        KeyModesOfUse modes = KeyModesOfUse.builder()
                .generate(true)
                .verify(true)
                .build();
        KeyAttributes attributes = KeyAttributes.builder()
                .keyAlgorithm(keyAlgorithm)
                .keyClass("SYMMETRIC_KEY")
                .keyUsage("TR31_V2_VISA_PIN_VERIFICATION_KEY")
                .keyModesOfUse(modes)
                .build();
                CreateKeyRequest request = CreateKeyRequest.builder()
                .keyAttributes(attributes)
                .enabled(true)
                .exportable(true)
                .build();
        PaymentCryptographyClient client = getControlPlaneClient();
        Key key = client.createKey(request).key();
        return key;
    }

    public static Key createCVVKey(String keyAlgorithm) throws InterruptedException, ExecutionException {
        KeyModesOfUse modes = KeyModesOfUse.builder()
                .generate(true)
                .verify(true)
                .build();
        KeyAttributes attributes = KeyAttributes.builder()
                .keyAlgorithm(keyAlgorithm)
                .keyClass("SYMMETRIC_KEY")
                .keyUsage("TR31_C0_CARD_VERIFICATION_KEY")
                .keyModesOfUse(modes)
                .build();
        CreateKeyRequest request = CreateKeyRequest.builder()
                .keyAttributes(attributes)
                .enabled(true)
                .exportable(true)
                .build();
        PaymentCryptographyClient  client = getControlPlaneClient();
        Key key = client.createKey(request).key();
        return key;
    }
}
