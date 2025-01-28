package aws.sample.paymentcryptography.pin;

import java.util.concurrent.ExecutionException;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import aws.sample.paymentcryptography.ServiceConstants;
import software.amazon.awssdk.services.paymentcryptography.model.Alias;
import software.amazon.awssdk.services.paymentcryptographydata.model.MajorKeyDerivationMode;
import software.amazon.awssdk.services.paymentcryptographydata.model.PinVerificationAttributes;
import software.amazon.awssdk.services.paymentcryptographydata.model.SessionKeyAmex;
import software.amazon.awssdk.services.paymentcryptographydata.model.SessionKeyDerivation;
import software.amazon.awssdk.services.paymentcryptographydata.model.VerifyAuthRequestCryptogramRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.VerifyPinDataRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.VisaPinVerification;

@RestController
public abstract class AbstractIssuerService {

    protected Alias issuerPekAlias = null;
    protected Alias pinValidationKeyAlias = null;
    protected Alias arqcValidationKeyAlias = null;

    protected AbstractIssuerService() throws InterruptedException, ExecutionException {
    }
    /* File based repository where the pin verification values (PVV) are store against the PAN.
     * The PVV is needed for PIN verification with the AWS Cryptography Service. In real scenario,
     * the PVV would be stored in a database.
    */
    @Autowired
    protected Repository repository;

    public abstract String setPinData(String encryptedPinBLock, @RequestParam String pan); 

    public abstract String pinAuthorizationFlow( String encryptedPin, @RequestParam String pan, @RequestParam String transactionData, @RequestParam String arqcCryptogram);

    protected VerifyPinDataRequest getVerifyPinDataRequest(String encryptedPinBlock, String encryptionKeyIdentifier,
            String verificationKeyIdentifer, String pinVerificationValue, String pinBlockFormat,
            String primaryAccountNumber) {

        VisaPinVerification visaPinVerification = VisaPinVerification
                .builder()
                .pinVerificationKeyIndex(ServiceConstants.PIN_VERIFICATION_KEY_INDEX)
                .verificationValue(pinVerificationValue)
                .build();
        PinVerificationAttributes pinVerificationAttributes = PinVerificationAttributes
                .builder()
                .visaPin(visaPinVerification)
                .build();

        VerifyPinDataRequest verifyPinDataRequest = VerifyPinDataRequest
                .builder().encryptedPinBlock(encryptedPinBlock)
                .verificationKeyIdentifier(verificationKeyIdentifer)
                .encryptionKeyIdentifier(encryptionKeyIdentifier)
                .primaryAccountNumber(primaryAccountNumber)
                .pinBlockFormat(pinBlockFormat)
                .verificationAttributes(pinVerificationAttributes)
                .build();
        return verifyPinDataRequest;
    }

    protected boolean verifyBalance() throws Exception {
        // Check if the balance is sufficient
        Logger.getGlobal().info("IssuerService:verifyBalance Attempting to verify balance");
        Thread.sleep(200);
        Logger.getGlobal().info("IssuerService:verifyBalance End verify balance");
        return true;
    }
    
    protected VerifyAuthRequestCryptogramRequest getVerifyARQCCryptogramRequest(String arqcCryptogram,
            String transactionData, String pan) {
        SessionKeyAmex amexAttributes = SessionKeyAmex.builder()
                .primaryAccountNumber(pan)
                .panSequenceNumber("00")
                .build();

        // Build session key derivation attributes
        SessionKeyDerivation derivationAttributes = SessionKeyDerivation.builder()
                .amex(amexAttributes)
                .build();

        // Create the verification request
        VerifyAuthRequestCryptogramRequest request = VerifyAuthRequestCryptogramRequest.builder()
                .authRequestCryptogram(arqcCryptogram)
                .keyIdentifier(arqcValidationKeyAlias.keyArn())
                .majorKeyDerivationMode(MajorKeyDerivationMode.EMV_OPTION_A)
                .transactionData(transactionData)
                .sessionKeyDerivationAttributes(derivationAttributes)
                .build();

        return request;
    }

    protected boolean validateTransaction(String transactionData) throws Exception {
        // Check if the balance is sufficient
        Logger.getGlobal().info("IssuerService:validateTransaction Attempting to verify balance");
        float authAmount = getAmount(transactionData);
        if (authAmount > 1000) {
            throw new Exception("Insufficient balance for requested amount " + authAmount);
        }
        if (authAmount < 0) {
            throw new Exception("Invalid amount requested - " + authAmount);
        }
        /* // Sleeping to simulate some time for processing
        Thread.sleep(200); */
        Logger.getGlobal().info("IssuerService:validateTransaction End verify balance");
        return true;
    }

    protected float getAmount(String transactionData) throws IllegalArgumentException{
        if(!isValidHexString(transactionData)) {
            throw new IllegalArgumentException("Transaction data not in hex format");
        }
        String amountString = transactionData.substring(0,12);
        return Float.parseFloat(amountString) / 100;
    }
    
    // Utility method to validate hex string
    protected static boolean isValidHexString(String hex) {
        return hex != null && hex.matches("^[0-9A-Fa-f]+$");
    }

    /*
     * Sample code to show how new pin genration can be done in the Payment Cryptography Service. This flow is currently not used in the samples.
    */
    /* private GeneratePinDataResponse generatePinData() {
        // finds or generates a Pin Generation Key (used for generating random PINs)
        if (null == pgkAlias.keyArn()) {
            System.out.println("No PGK found, creating a new one.");
            Key pgkKey = ControlPlaneUtils.createVisaPGK(ServiceConstants.PGK_ALGORITHM);
            pgkAlias = ControlPlaneUtils.upsertAlias(pgkAliasName, pgkKey.keyArn());
            System.out.println(String.format("PGK created: %s", pgkAlias.keyArn()));
        } else {
            System.out.println(String.format("PGK already exists: %s", pgkAlias.keyArn()));
        }

        // finds existing or generates a Pin Encryption Key (used for encryption pin
        // payloads)
        if (null == pekAlias.keyArn()) {
            System.out.println("No PEK found, creating a new one.");
            Key pekKey = ControlPlaneUtils.createPEK(ServiceConstants.PEK_ALGORITHM);
            pekAlias = ControlPlaneUtils.upsertAlias(pekAliasName, pekKey.keyArn());
            System.out.println(String.format("PEK created: %s", pekAlias.keyArn()));
        } else {
            System.out.println(String.format("PEK already exists: %s", pekAlias.keyArn()));
        }

        // Generate a BDK used as the base deriviation key typically for DUKPT
        if (null == bdkAlias.keyArn()) {
            System.out.println("No BDK found, creating a new one.");
            Key bdkKey = ControlPlaneUtils.createBDK(ServiceConstants.BDK_ALGORITHM);
            bdkAlias = ControlPlaneUtils.upsertAlias(bdkAliasName, bdkKey.keyArn());
            System.out.println(String.format("BDK created: %s", bdkAlias.keyArn()));
        } else {
            System.out.println(String.format("BDK already exists: %s", bdkAlias.keyArn()));
        }
        System.out.println("Creating a random pin and returns back the encrypted pin and visa/ABA PVV");
        GeneratePinDataResponse pinDataGenerationResponse = DataPlaneUtils.generateVisaPinBlock(
                pekAliasName,
                pgkAliasName,
                ServiceConstants.ISO_0_PIN_BLOCK_FORMAT,
                ServiceConstants.PAN,
                ServiceConstants.PIN_VERIFICATION_KEY_INDEX);
        System.out.println(String.format("PIN block: %s", pinDataGenerationResponse.encryptedPinBlock()));

        System.out.println("Translating encrypted PIN under PEK to encrypted under DUKPT");
        String pinBlockUnderBDK = DataPlaneUtils.translateVisaPinBlockPekToBdk(
                pekAliasName,
                ServiceConstants.ISO_0_PIN_BLOCK_FORMAT,
                pinDataGenerationResponse.encryptedPinBlock(),
                bdkAliasName,
                ServiceConstants.ISO_3_PIN_BLOCK_FORMAT,
                ServiceConstants.BDK_ALGORITHM,
                ServiceConstants.KSN,
                ServiceConstants.PAN);

        System.out.println(String.format("Translated PIN block: %s", pinBlockUnderBDK));
        return pinDataGenerationResponse;
    } */

    protected Repository getRepository() {
        return repository;
    }

    protected void setRepository(Repository repository) {
        this.repository = repository;
    }
}
