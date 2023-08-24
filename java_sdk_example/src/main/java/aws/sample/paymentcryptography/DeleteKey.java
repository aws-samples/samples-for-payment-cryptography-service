package aws.sample.paymentcryptography;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.amazonaws.services.paymentcryptography.AWSPaymentCryptographyAsync;
import com.amazonaws.services.paymentcryptography.model.DeleteKeyRequest;
import com.amazonaws.services.paymentcryptography.model.DeleteKeyResult;
import com.amazonaws.services.paymentcryptography.model.KeySummary;
import com.amazonaws.services.paymentcryptography.model.ListKeysRequest;
import com.amazonaws.services.paymentcryptography.model.ListKeysResult;

public class DeleteKey {

    private static final AWSPaymentCryptographyAsync client = ControlPlaneUtils.getControlPlaneClient();
    private static final String ALL_KEYS = "all-keys";

    public static void main(String[] args) {
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
        }
    }

    private static void deleteAllKeys() {
        AWSPaymentCryptographyAsync client = ControlPlaneUtils.getControlPlaneClient();
        ListKeysRequest request = new ListKeysRequest().withMaxResults(20);
        ListKeysResult result = client.listKeys(request);
        List<KeySummary> keySummaries = result.getKeys();
        while (null != keySummaries) {
            for (KeySummary keySummary : keySummaries) {
                // Only delete keys that are in CREATE_COMPLETE state and skip the ones that are in pending deletion state etc.
                if (keySummary.getKeyState().equals("CREATE_COMPLETE")) {
                    System.out.println("Attempting to delete key - " + keySummary.getKeyArn());
                    deleteKey(keySummary);
                }
            }
            if (null != result.getNextToken()) {
                System.out.println("Requesting another page of keys...");
                result = client.listKeys(request.withNextToken(result.getNextToken()));
                keySummaries = result.getKeys();
            } else {
                System.out.println("Reached the last page of keys.");
                keySummaries = null;
            }
        }
    }

    private static boolean deleteKey(KeySummary keySummary) throws IllegalArgumentException {
        if (keySummary == null)
            throw new IllegalArgumentException("Null alias passed");
        return deleteKey(keySummary.getKeyArn());
    }

    private static boolean deleteKey(String keyARN) {
        DeleteKeyRequest deleteRequest = new DeleteKeyRequest().withKeyIdentifier(keyARN);
        DeleteKeyResult deleteResult = client.deleteKey(deleteRequest);
        boolean deleted = deleteResult.getSdkHttpMetadata().getHttpStatusCode() == 200;
        if (deleted) {
            System.out.println(String.format("Key %s deleted", keyARN));
        } else {
            System.out.println(String.format("Key %s not deleted", keyARN));
        }
        return deleted;
    }
}