package aws.sample.paymentcryptography.pin;

import java.util.concurrent.ExecutionException;

import org.json.JSONObject;
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
    protected String PAN_SEQUENCE_NUMBER = "00";
    protected String HEX_REGEX = "^[0-9A-Fa-f]+$";

    protected enum RETURN_REASON_CODES {
        APPROVED,
        DECLINED,
        INSUFFICIENT_FUNDS
    };

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

    protected VerifyAuthRequestCryptogramRequest getVerifyARQCCryptogramRequest(String arqcCryptogram,
            String transactionData, String pan) {
        SessionKeyAmex amexAttributes = SessionKeyAmex.builder()
                .primaryAccountNumber(pan)
                .panSequenceNumber(PAN_SEQUENCE_NUMBER)
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

    protected JSONObject validateTransaction(String transactionData) throws Exception {
        JSONObject response = new JSONObject();
        float authAmount = getAmount(transactionData);
        if (authAmount > 1000) {
            response.put("status",RETURN_REASON_CODES.DECLINED.name());
            response.put("reason", "Transaction over limit");
        }else {
            response.put("status", RETURN_REASON_CODES.APPROVED.name());
        }
        return response;
    }

    protected float getAmount(String transactionData) throws IllegalArgumentException{
        if(!isValidHexString(transactionData)) {
            throw new IllegalArgumentException("Transaction data not in hex format");
        }
        String amountString = transactionData.substring(0,12);
        return Float.parseFloat(amountString) / 100;
    }
    
    // Utility method to validate hex string
    protected boolean isValidHexString(String hex) {
        return hex != null && hex.matches(HEX_REGEX);
    }

    protected Repository getRepository() {
        return repository;
    }

    protected void setRepository(Repository repository) {
        this.repository = repository;
    }
}
