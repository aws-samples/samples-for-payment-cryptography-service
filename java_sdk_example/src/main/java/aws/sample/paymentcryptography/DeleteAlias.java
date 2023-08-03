package aws.sample.paymentcryptography;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.amazonaws.services.paymentcryptography.AWSPaymentCryptography;
import com.amazonaws.services.paymentcryptography.model.Alias;
import com.amazonaws.services.paymentcryptography.model.DeleteAliasRequest;
import com.amazonaws.services.paymentcryptography.model.DeleteAliasResult;
import com.amazonaws.services.paymentcryptography.model.DeleteKeyRequest;
import com.amazonaws.services.paymentcryptography.model.DeleteKeyResult;
import com.amazonaws.services.paymentcryptography.model.GetAliasRequest;
import com.amazonaws.services.paymentcryptography.model.ListAliasesRequest;
import com.amazonaws.services.paymentcryptography.model.ListAliasesResult;

public class DeleteAlias {

    private static final AWSPaymentCryptography client = ControlPlaneUtils.getControlPlaneClient();
    private static final String ALL_ALIASES = "all-aliases";

    public static void main(String[] args) {
        List<String> aliasesToDelete = null;
        boolean deleteKey = false;

        if (args.length > 0) {
            String aliasToDelete = args[0];
            if(args.length>1 && args[1]=="delete-key"){
                deleteKey = true;
            }
            if (true) {
                deleteAllAliases(deleteKey);
            } /* else {
                aliasesToDelete = new ArrayList<String>();
                aliasesToDelete.addAll(Arrays.asList(aliasToDelete.split(",")));
                for (String aliasName : aliasesToDelete) {
                    Alias alias = client.getAlias(new GetAliasRequest().withAliasName(aliasName)).getAlias();
                    deleteAlias(alias,deleteKey);
                }
            } */
        }
    }

    private static void deleteAllAliases(boolean deleteKey) {
        AWSPaymentCryptography client = ControlPlaneUtils.getControlPlaneClient();
        ListAliasesRequest request = new ListAliasesRequest().withMaxResults(10);
        ListAliasesResult result = client.listAliases(request);
        List<Alias> aliases = result.getAliases();
        while (null != aliases) {
            for (Alias alias : aliases) {
                deleteAlias(alias,deleteKey);
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

    private static void deleteAlias(Alias alias, boolean deleteKey) throws IllegalArgumentException {
        if (alias == null)
            throw new IllegalArgumentException("Null alias passed");
        deleteAlias(alias.getAliasName());
        if(deleteKey) {
            deleteKey(alias.getKeyArn());    
        }
    }

    private static boolean deleteAlias(String aliasName) {
        DeleteAliasRequest deleteRequest = new DeleteAliasRequest().withAliasName(aliasName);
        DeleteAliasResult deleteResult = client.deleteAlias(deleteRequest);
        boolean deleted = deleteResult.getSdkHttpMetadata().getHttpStatusCode() == 200;
        if (deleted) {
            System.out.println(String.format("Alias %s deleted", aliasName));
        } else {
            System.out.println(String.format("Alias %s not deleted", aliasName));
        }
        return deleted;
    }

    private static boolean deleteKey(String keyARN) {
        DeleteKeyRequest deleteKeyRequest = new DeleteKeyRequest().withKeyIdentifier(keyARN);
        DeleteKeyResult deleteKeyResult = ControlPlaneUtils.getControlPlaneClient().deleteKey(deleteKeyRequest);
        if (deleteKeyResult.getSdkHttpMetadata().getHttpStatusCode() == 200) {
            System.out.println(String.format("Key %s deleted", keyARN));
        } else {
            System.out.println(String.format("Key %s not deleted", keyARN));
        }
        return deleteKeyResult.getSdkHttpMetadata().getHttpStatusCode() == 200;
    }
}