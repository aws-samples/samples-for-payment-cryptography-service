package aws.sample.paymentcryptography;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;

import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.paymentcryptography.PaymentCryptographyClient;
import software.amazon.awssdk.services.paymentcryptography.model.Alias;
import software.amazon.awssdk.services.paymentcryptography.model.DeleteAliasRequest;
import software.amazon.awssdk.services.paymentcryptography.model.GetAliasRequest;
import software.amazon.awssdk.services.paymentcryptography.model.GetAliasResponse;
import software.amazon.awssdk.services.paymentcryptography.model.ListAliasesRequest;;
/* 
 * Usage - 
 * 
 * To delete all aliases
 * ./run_example.sh aws.sample.paymentcryptography.DeleteAliasUtil all-aliases
 * 
 * OR 
 * To delete individual alias
 * ./run_example.sh aws.sample.paymentcryptography.DeleteAliasUtil alias/MerchantTerminal_BDK
 * 
 */

public class DeleteAliasUtil {

    private static final PaymentCryptographyClient client = ControlPlaneUtils.getControlPlaneClient();
    private static final String ALL_ALIASES = "all-aliases";

    public static void main(String[] args) throws IllegalArgumentException, InterruptedException, ExecutionException {
        List<String> aliasesToDelete = null;

        if (args.length > 0) {
            String aliasToDelete = args[0];
            if (aliasToDelete.equals(ALL_ALIASES)) {
                deleteAllAliases();
            } else {
                aliasesToDelete = new ArrayList<String>();
                aliasesToDelete.addAll(Arrays.asList(aliasToDelete.split(",")));
                for (String aliasName : aliasesToDelete) {
                    GetAliasResponse aliasResponse = client
                            .getAlias(GetAliasRequest.builder().aliasName(aliasName).build());
                    deleteAlias(aliasResponse.alias());
                }
            }
        }
    }

    private static void deleteAllAliases() throws InterruptedException, ExecutionException {
        System.out.println("delete all aliases...");
        ListAliasesRequest request = ListAliasesRequest.builder().maxResults(10).build();
        List<Alias> aliases = client.listAliases(request).aliases();
        if (aliases.isEmpty()) {
            System.out.println("No aliases found");
        }
        for (Alias alias : aliases) {
            deleteAlias(alias);
        }
    }

    private static void deleteAlias(Alias alias)
            throws IllegalArgumentException, InterruptedException, ExecutionException {
        if (alias == null)
            throw new IllegalArgumentException("Null alias passed");
        deleteAlias(alias.aliasName());
    }

    private static boolean deleteAlias(String aliasName) throws InterruptedException, ExecutionException {
        DeleteAliasRequest deleteRequest = DeleteAliasRequest.builder().aliasName(aliasName).build();
        SdkHttpResponse response = client.deleteAlias(deleteRequest).sdkHttpResponse();
        boolean deleted = response.statusCode() == 200;

        if (deleted) {
            System.out.println(String.format("Alias %s deleted", aliasName));
        } else {
            System.out.println(String.format("Alias %s not deleted", aliasName));
        }
        return deleted;
    }

    /*
     * Use this method if you also want to delete key of the alias - while deleting
     * the alias
     */
    /*
     * private static boolean deleteKey(String keyARN) {
     * System.out.println("deleting key " + keyARN);
     * DeleteKeyRequest deleteKeyRequest = new
     * DeleteKeyRequest().withKeyIdentifier(keyARN);
     * DeleteKeyResult deleteKeyResult =
     * ControlPlaneUtils.getControlPlaneClient().deleteKey(deleteKeyRequest);
     * if (deleteKeyResult.getSdkHttpMetadata().getHttpStatusCode() == 200) {
     * System.out.println(String.format("Key %s deleted", keyARN));
     * } else {
     * System.out.println(String.format("Key %s not deleted", keyARN));
     * }
     * return deleteKeyResult.getSdkHttpMetadata().getHttpStatusCode() == 200;
     * }
     */
}