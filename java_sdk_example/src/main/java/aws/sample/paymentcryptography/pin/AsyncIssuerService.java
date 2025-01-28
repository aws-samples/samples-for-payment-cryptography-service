package aws.sample.paymentcryptography.pin;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.logging.Logger;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import aws.sample.paymentcryptography.ControlPlaneUtils;
import aws.sample.paymentcryptography.DataPlaneUtils;
import aws.sample.paymentcryptography.ServiceConstants;
import software.amazon.awssdk.services.paymentcryptographydata.PaymentCryptographyDataAsyncClient;
import software.amazon.awssdk.services.paymentcryptographydata.model.GeneratePinDataRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.GeneratePinDataResponse;
import software.amazon.awssdk.services.paymentcryptographydata.model.PinGenerationAttributes;
import software.amazon.awssdk.services.paymentcryptographydata.model.VerifyAuthRequestCryptogramRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.VerifyAuthRequestCryptogramResponse;
import software.amazon.awssdk.services.paymentcryptographydata.model.VerifyPinDataRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.VerifyPinDataResponse;
import software.amazon.awssdk.services.paymentcryptographydata.model.VisaPinVerificationValue;

@RestController
public class AsyncIssuerService extends AbstractIssuerService {

    PaymentCryptographyDataAsyncClient asyncClient = DataPlaneUtils.getDataPlaneAsyncClient();

    public AsyncIssuerService() throws InterruptedException, ExecutionException {
        super();
        issuerPekAlias = ControlPlaneUtils.getOrCreateAliasAsync(ServiceConstants.ISSUER_PEK_ALIAS, null);
        pinValidationKeyAlias = ControlPlaneUtils.getOrCreateAliasAsync(ServiceConstants.PIN_VALIDATION_KEY_ALIAS,
                null);
        arqcValidationKeyAlias = ControlPlaneUtils.getOrCreateAliasAsync(ServiceConstants.ARQC_Retail_9797_3_KEY_ALIAS,
                null);
    }

    /*
     * File based repository where the pin verification values (PVV) are store
     * against the PAN.
     * The PVV is needed for PIN verification with the AWS Cryptography Service. In
     * real scenario,
     * the PVV would be stored in a database.
     */
    @Autowired
    private Repository repository;

    @GetMapping(ServiceConstants.ISSUER_SERVICE_PIN_SET_API_ASYNC)
    @ResponseBody
    public String setPinData(@RequestParam String encryptedPinBLock, @RequestParam String pan) {
        Logger.getGlobal().info("AsyncIssuerService:setPinData Attempting to set PIN for encrypted PIN Block - "
                + encryptedPinBLock + " with PAN " + pan);
        JSONObject response = new JSONObject();

        try {
            VisaPinVerificationValue pinVerificationValue = VisaPinVerificationValue
                    .builder()
                    .encryptedPinBlock(encryptedPinBLock)
                    .pinVerificationKeyIndex(ServiceConstants.PIN_VERIFICATION_KEY_INDEX)
                    .build();
            PinGenerationAttributes attributes = PinGenerationAttributes
                    .builder()
                    .visaPinVerificationValue(pinVerificationValue)
                    .build();
            GeneratePinDataRequest request = GeneratePinDataRequest
                    .builder()
                    .generationKeyIdentifier(pinValidationKeyAlias.keyArn())
                    .encryptionKeyIdentifier(issuerPekAlias.keyArn())
                    .primaryAccountNumber(pan)
                    .pinBlockFormat(ServiceConstants.ISO_0_PIN_BLOCK_FORMAT)
                    .generationAttributes(attributes)
                    .build();

            CompletableFuture<GeneratePinDataResponse> futureResponse = asyncClient.generatePinData(request);
            return futureResponse.thenApply(generatePinResponse -> {
                Logger.getGlobal().info(
                        "AsyncIssuerService:setPinData Set PIN Data successful for encrypted PIN Block "
                                + encryptedPinBLock);
                Logger.getGlobal().info("Setting PVV in repo");
                try {
                    getRepository().addEntry(pan, generatePinResponse.pinData().verificationValue());
                    Logger.getGlobal().info("Done setting PVV in repo");
                    response.put("status", "ok");
                    Logger.getGlobal().info("Set Pin Complete");
                } catch (IOException e) {
                    response.put("status", "fail");
                    throw new CompletionException(e);
                }
                return response.toString();
                // return generatePinResponse;
            }).exceptionally(exception -> {
                Logger.getGlobal().info(
                        "AsyncIssuerService:setPinData Set PIN Data failed for encrypted PIN Block " + exception);
                return response.toString();
                // throw new CompletionException(exception);

            }).join();
        } catch (Exception exception) {
            response.put("error", exception.getMessage());
            exception.printStackTrace();
            return response.toString();
        }
    }

    @GetMapping(ServiceConstants.ISSUER_SERVICE_PIN_VERIFY_API_ASYNC)
    @ResponseBody
    public String pinAuthorizationFlow(@RequestParam String encryptedPin, @RequestParam String pan,
            @RequestParam String transactionData, @RequestParam String arqcCryptogram) {
        JSONObject response = new JSONObject();
        try {
            Logger.getGlobal().info("AsyncIssuerService:pinFlow PIN and ARQC, PIN Block - " + encryptedPin
                    + " with PAN " + pan + " ARQC " + arqcCryptogram);

            CompletableFuture<VerifyPinDataResponse> verifyPinDataTask = verifyPinDataAsync(encryptedPin,
                    issuerPekAlias.keyArn(),
                    pinValidationKeyAlias.keyArn(), getRepository().getEntry(pan),
                    ServiceConstants.ISO_0_PIN_BLOCK_FORMAT, pan);
            CompletableFuture<Boolean> balanceVerifyTask = validateTransactionAsync(transactionData);
            CompletableFuture<VerifyAuthRequestCryptogramResponse> arqcCryptogramValidationTask = verifyARQCCryptogramAsync(
                    arqcCryptogram, transactionData, pan);

            CompletableFuture<?>[] futureTasks = { balanceVerifyTask, arqcCryptogramValidationTask, verifyPinDataTask };
            // Wait for all futures to complete
            CompletableFuture.allOf(futureTasks).thenApply(v -> {
                Logger.getGlobal().info("All tasks completed!");
                // All futures have completed here, so response object is fully populated
                response.put("status", "valid");
                return response.toString();
            }).exceptionally(throwable -> {
                throw new CompletionException(throwable);
            });
            return response.toString();
        } catch (Exception exception) {
            exception.printStackTrace();
            response.put("status", "fail");
            return response.toString();
        }
    }

    private CompletableFuture<VerifyPinDataResponse> verifyPinDataAsync(String encryptedPinBlock,
            String encryptionKeyIdentifier,
            String verificationKeyIdentifer, String pinVerificationValue, String pinBlockFormat,
            String primaryAccountNumber) {

        VerifyPinDataRequest verifyPinDataRequest = getVerifyPinDataRequest(encryptedPinBlock, encryptionKeyIdentifier,
                verificationKeyIdentifer, pinVerificationValue, pinBlockFormat, primaryAccountNumber);

        Logger.getGlobal().info(
                "STEP A - verifyPinData Attempting to verify PIN for encrypted PIN block "
                        + encryptedPinBlock);

        return asyncClient.verifyPinData(verifyPinDataRequest)
                .thenApply(response -> {
                    Logger.getGlobal()
                            .info("STEP A - verifyPinData PIN verification completed successfully "
                                    + response.verificationKeyCheckValue());
                    return response;
                }).exceptionally(t -> {
                    Logger.getGlobal().info(
                            "STEP A - verifyPinData PIN verification failed " + t.getMessage());
                    throw new CompletionException(t);
                });
    }

    protected CompletableFuture<Boolean> validateTransactionAsync(String transactionData) throws Exception {
        CompletableFuture<Boolean> futureVerifyBalance = CompletableFuture.supplyAsync(() -> {
            // Check if the balance is sufficient
            try {
                Logger.getGlobal().info("STEP B - validateTransactionAsync");
                boolean transactionValid = validateTransaction(transactionData);
                Logger.getGlobal().info("STEP B - validateTransactionAsync");
                return transactionValid;
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });

        return futureVerifyBalance;
    }

    protected CompletableFuture<VerifyAuthRequestCryptogramResponse> verifyARQCCryptogramAsync(String arqcCryptogram,
            String transactionData, String pan) {
        Logger.getGlobal().info("STEP C - verifyARQCCryptogram " + arqcCryptogram + " pan " + pan);
        VerifyAuthRequestCryptogramRequest verifyAuthRequestCryptogramRequest = getVerifyARQCCryptogramRequest(
                arqcCryptogram, transactionData, pan);

        return asyncClient.verifyAuthRequestCryptogram(verifyAuthRequestCryptogramRequest)
                .thenApply(response -> {
                    Logger.getGlobal().info("STEP C - verifyARQCCryptogram completed successfully "
                            + response.keyCheckValue());
                    return response;
                }).exceptionally(t -> {
                    Logger.getGlobal().info("STEP C - verifyARQCCryptogram failed " + t.getMessage());
                    throw new CompletionException(t);
                });
    }

    public Repository getRepository() {
        return repository;
    }

    public void setRepository(Repository repository) {
        this.repository = repository;
    }
}
