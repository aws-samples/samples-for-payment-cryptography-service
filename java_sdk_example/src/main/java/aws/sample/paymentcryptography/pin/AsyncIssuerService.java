package aws.sample.paymentcryptography.pin;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
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

    // GET API for simplicity. In production scenarios, this would typically be a POST API
    @GetMapping(ServiceConstants.ISSUER_SERVICE_PIN_SET_API_ASYNC)
    @ResponseBody
    public String setPinData(@RequestParam String encryptedPinBLock, @RequestParam String pan) {
        Logger.getGlobal().log(Level.INFO,
                "AsyncIssuerService:setPinData Attempting to set PIN for encrypted PIN Block {0} with PAN {1} ",
                new Object[] { encryptedPinBLock, pan });
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
                Logger.getGlobal().log(Level.INFO,
                        "AsyncIssuerService:setPinData Set PIN Data successful for encrypted PIN Block {0}", encryptedPinBLock);
                Logger.getGlobal().log(Level.INFO,"Setting PVV in repo");
                try {
                    getRepository().addEntry(pan, generatePinResponse.pinData().verificationValue());
                    Logger.getGlobal().log(Level.INFO,"Done setting PVV in repo");
                    response.put("status", "ok");
                    Logger.getGlobal().log(Level.INFO,"Set Pin Complete");
                } catch (IOException e) {
                    response.put("status", "fail");
                    throw new CompletionException(e);
                }
                return response.toString();
                // return generatePinResponse;
            }).exceptionally(exception -> {
                Logger.getGlobal().log(Level.INFO,
                        "AsyncIssuerService:setPinData Set PIN Data failed for encrypted PIN Block {0}" + exception);
                return response.toString();
                // throw new CompletionException(exception);

            }).join();
        } catch (Exception exception) {
            response.put("error", exception.getMessage());
            exception.printStackTrace();
            return response.toString();
        }
    }

    // GET API for simplicity. In production scenarios, this would typically be a POST API
    @GetMapping(ServiceConstants.ISSUER_SERVICE_PIN_VERIFY_API_ASYNC)
    @ResponseBody
    public String pinAuthorizationFlow(@RequestParam String encryptedPin, @RequestParam String pan,
            @RequestParam String transactionData, @RequestParam String arqcCryptogram) {
        try {
            Logger.getGlobal().log(Level.INFO,"AsyncIssuerService:pinAuthorizationFlow PIN and ARQC, PIN Block {0}, with PAN {1}, ARQC {2}" , new Object[] {encryptedPin,pan,arqcCryptogram});

            CompletableFuture<VerifyPinDataResponse> verifyPinDataTask = verifyPinDataAsync(encryptedPin,
                    issuerPekAlias.keyArn(),
                    pinValidationKeyAlias.keyArn(), getRepository().getEntry(pan),
                    ServiceConstants.ISO_0_PIN_BLOCK_FORMAT, pan);
            CompletableFuture<JSONObject> balanceVerifyTask = validateTransactionAsync(transactionData);
            CompletableFuture<VerifyAuthRequestCryptogramResponse> arqcCryptogramValidationTask = verifyARQCCryptogramAsync(
                    arqcCryptogram, transactionData, pan);

            CompletableFuture<?>[] futureTasks = { balanceVerifyTask, arqcCryptogramValidationTask, verifyPinDataTask };
            // Wait for all futures to complete
            return CompletableFuture.allOf(futureTasks).thenApply(v -> {
                Logger.getGlobal().log(Level.INFO,"All tasks completed!");
                // All futures have completed here, so response object is fully populated
                return balanceVerifyTask.join();
            }).exceptionally(throwable -> {
                throw new CompletionException(throwable);
            }).join().toString();
        } catch (Exception exception) {
            exception.printStackTrace();
            JSONObject response = new JSONObject();
            response.put("status", "fail");
            response.put("reason", exception.getMessage());
            return response.toString();
        }
    }

    private CompletableFuture<VerifyPinDataResponse> verifyPinDataAsync(String encryptedPinBlock,
            String encryptionKeyIdentifier,
            String verificationKeyIdentifer, String pinVerificationValue, String pinBlockFormat,
            String primaryAccountNumber) {

        VerifyPinDataRequest verifyPinDataRequest = getVerifyPinDataRequest(encryptedPinBlock, encryptionKeyIdentifier,
                verificationKeyIdentifer, pinVerificationValue, pinBlockFormat, primaryAccountNumber);

        Logger.getGlobal().log(Level.INFO,
                "STEP A Start - verifyPinData for encrypted PIN block {0}", encryptedPinBlock);

        return asyncClient.verifyPinData(verifyPinDataRequest)
                .thenApply(response -> {
                    Logger.getGlobal().log(Level.INFO,
                            "STEP A Complete - verifyPinData successful, berification KCV {0}",
                            response.verificationKeyCheckValue());

                    return response;
                }).exceptionally(t -> {
                    Logger.getGlobal().log(Level.INFO, "STEP A Error - verifyPinData failed for encrypted PIN block {0}",
                            t.getMessage());
                    throw new CompletionException(t);
                });
    }

    protected CompletableFuture<JSONObject> validateTransactionAsync(String transactionData) throws Exception {
        CompletableFuture<JSONObject> futureVerifyBalance = CompletableFuture.supplyAsync(() -> {
            // Check if the balance is sufficient
            try {
                Logger.getGlobal().log(Level.INFO, "STEP B Start - validateTransactionAsync");
                JSONObject transactionValidationStatus = validateTransaction(transactionData);
                Logger.getGlobal().log(Level.INFO, "STEP B Complete - validateTransactionAsync");
                return transactionValidationStatus;
            } catch (Exception e) {
                Logger.getGlobal().log(Level.INFO, "STEP B Error - validateTransactionAsync");
                throw new CompletionException(e);
            }
        });

        return futureVerifyBalance;
    }

    protected CompletableFuture<VerifyAuthRequestCryptogramResponse> verifyARQCCryptogramAsync(String arqcCryptogram,
            String transactionData, String pan) {
        Logger.getGlobal().log(Level.INFO, "STEP C Start - verifyARQCCryptogram {0} pan {1}",
                new Object[] { arqcCryptogram, pan });
        VerifyAuthRequestCryptogramRequest verifyAuthRequestCryptogramRequest = getVerifyARQCCryptogramRequest(
                arqcCryptogram, transactionData, pan);

        return asyncClient.verifyAuthRequestCryptogram(verifyAuthRequestCryptogramRequest)
                .thenApply(response -> {
                    Logger.getGlobal().log(Level.INFO, "STEP C Complete - verifyARQCCryptogram completed successfully {0}", response.keyCheckValue());
                    return response;
                }).exceptionally(t -> {
                    Logger.getGlobal().log(Level.INFO, "STEP C Error - verifyARQCCryptogram failed {0}", t.getMessage());
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
