package aws.sample.paymentcryptography;

/* 
 * Constants for both client side terminal and server side services. In real scenario, this would be separate for client and server classes.
 */
public interface CommonConstants {
    
    public final String MODE = "CBC";

    public final String HOST = "http://localhost:8080";

    public static final String ISSUER_SERVICE_PIN_SET_API = "/issuer/setPin/";
    public static final String ISSUER_SERVICE_PIN_SET_API_ASYNC = "/issuer/setPinAsync/";
    public static final String ISSUER_SERVICE_PIN_VERIFY_API = "/issuer/pinAuthorization/";
    public static final String ISSUER_SERVICE_PIN_VERIFY_API_ASYNC = "/issuer/pinAuthorizationAsync/";
    public static final String PIN_PROCESSOR_SERVICE_PIN_SET_API = "/pin-processor-service/setPin/";
    public static final String PIN_PROCESSOR_SERVICE_ISO_0_FORMAT_PIN_VERIFY_API = "/pin-processor-service/verifyPin_iso_0_format/";
    public static final String PIN_PROCESSOR_SERVICE_ISO_4_FORMAT_PIN_VERIFY_API = "/pin-processor-service/verifyPin_iso_4_format/";
    public static final String PAYMENT_PROCESSOR_SERVICE_AUTHORIZE_PAYMENT_API = "/payment-processor/authorizePayment/";

}
