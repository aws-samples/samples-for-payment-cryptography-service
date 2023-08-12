package aws.sample.paymentcryptography;

/* 
 * Constants for both client side terminal and server side services. In real scenario, this would be separate for client and server classes.
 */
public interface CommonConstants {
    
    public final String PAN = "9123412341234";
    
    public final String KSN = "FFFF9876543210E00001"; 

    public final String MODE = "CBC";

    public final String HOST = "http://localhost:8080";

    public static final String ISSUER_SERVICE_PIN_SET_API = "/issuer/setPin/";
    public static final String ISSUER_SERVICE_PIN_VERIFY_API = "/issuer/verifyPin/";
    public static final String PIN_PROCESSOR_SERVICE_PIN_SET_API = "/pin-processor-service/setPin/";
    public static final String PIN_PROCESSOR_SERVICE_PIN_VERIFY_API = "/pin-processor-service/verifyPin/";
    public static final String PAYMENT_PROCESSOR_SERVICE_AUTHORIZE_PAYMENT_API = "/payment-processor/authorizePayment/";

    public static final String HMAC_DATA_PLAIN_TEXT = "Sample-HMAC-Test-Data-1313";

}
