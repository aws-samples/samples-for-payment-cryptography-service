package aws.sample.paymentcryptography;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.amazonaws.services.paymentcryptography.AWSPaymentCryptographyAsync;
import com.amazonaws.services.paymentcryptography.model.Alias;
import com.amazonaws.services.paymentcryptography.model.DeleteKeyRequest;
import com.amazonaws.services.paymentcryptography.model.DeleteKeyResult;
import com.amazonaws.services.paymentcryptography.model.ListAliasesRequest;
import com.amazonaws.services.paymentcryptography.model.ListAliasesResult;

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
        ListAliasesRequest request = new ListAliasesRequest().withMaxResults(10);
        ListAliasesResult result = client.listAliases(request);
        List<Alias> aliases = result.getAliases();
        while (null != aliases) {
            for (Alias alias : aliases) {
                deleteKey(alias);
            }
            if (null != result.getNextToken()) {
                System.out.println("Requesting another page of aliases...");
                result = client.listAliases(request.withNextToken(result.getNextToken()));
                aliases = result.getAliases();
            } else {
                System.out.println("Reached the last page of aliases.");
                aliases = null;
            }
        }
    }

    private static boolean deleteKey(Alias alias) throws IllegalArgumentException {
        if (alias == null)
            throw new IllegalArgumentException("Null alias passed");
        return deleteKey(alias.getKeyArn());
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