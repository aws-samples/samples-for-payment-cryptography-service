package aws.sample.paymentcryptography;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.paymentcryptography.PaymentCryptographyClient;
import software.amazon.awssdk.services.paymentcryptography.model.DeleteKeyRequest;
import software.amazon.awssdk.services.paymentcryptography.model.KeySummary;
import software.amazon.awssdk.services.paymentcryptography.model.ListKeysRequest;

/* 
 * Usage - 
 * 
 * To Delete All Keys - 
 * ./run_example.sh aws.sample.paymentcryptography.DeleteKey all-keys
 * 
 * OR to delete individual key
 * ./run_example.sh aws.sample.paymentcryptography.DeleteKey arn:aws:payment-cryptography:us-east-1:XXXXXXXXXX:key/jvljh5wzjhvgadyy
 */
public class DeleteKeyUtil {

    private static final PaymentCryptographyClient client = ControlPlaneUtils.getControlPlaneClient();
    private static final String ALL_KEYS = "all-keys";

    public static void main(String[] args) throws InterruptedException, ExecutionException {
        List<String> keysToDelete = null;
        
        if (args.length > 0) {
            String arg = args[0];
            if (arg.equals(ALL_KEYS)) {
                deleteAllKeys();
            } else {
                keysToDelete = new ArrayList<String>();
                keysToDelete.addAll(Arrays.asList(arg.split(",")));
                for (String keyName : keysToDelete) {
                    deleteKey(keyName);
                }
            }
        } else {
            Logger.getGlobal().log(Level.INFO,"No keys passed to delete");
        }
    }

    private static void deleteAllKeys() throws InterruptedException, ExecutionException {
        ListKeysRequest request = ListKeysRequest.builder().maxResults(100).build();
        List<KeySummary> keySummaries = client.listKeys(request).keys();
        if (keySummaries.size() == 0) {
            Logger.getGlobal().log(Level.INFO,"No keys to delete");
            return;
        }
        for (KeySummary keySummary : keySummaries) {
            // Only delete keys that are in CREATE_COMPLETE state and skip the ones that are
            // in pending deletion state etc.
            if (keySummary.keyState().toString().equals("CREATE_COMPLETE")) {
                Logger.getGlobal().log(Level.INFO,"Attempting to delete key {0}" , keySummary.keyArn());
                deleteKey(keySummary);
                Logger.getGlobal().log(Level.INFO,"Deleted key {0}" , keySummary.keyArn());
            }else {
                Logger.getGlobal().log(Level.INFO,"Skipping key {0} since it's key state is {1}" , new Object[] {keySummary.keyArn(),keySummary.keyState()});
            }
        }
    }

    private static boolean deleteKey(KeySummary keySummary)
            throws IllegalArgumentException, InterruptedException, ExecutionException {
        if (keySummary == null)
            throw new IllegalArgumentException("Null key summary passed");
        return deleteKey(keySummary.keyArn());
    }

    private static boolean deleteKey(String keyARN) throws InterruptedException, ExecutionException {
        DeleteKeyRequest deleteRequest = DeleteKeyRequest.builder().keyIdentifier(keyARN).build();
        SdkHttpResponse deleteResponse = client.deleteKey(deleteRequest).sdkHttpResponse();
        boolean deleted = deleteResponse.statusCode() == 200;
        if (deleted) {
            Logger.getGlobal().log(Level.INFO,String.format("Key %s deleted", keyARN));
        } else {
            Logger.getGlobal().log(Level.INFO,String.format("Key %s not deleted", keyARN));
        }
        return deleted;
    }
}