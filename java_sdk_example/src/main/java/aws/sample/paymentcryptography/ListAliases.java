package aws.sample.paymentcryptography;

import java.util.List;

import com.amazonaws.services.paymentcryptography.AWSPaymentCryptography;
import com.amazonaws.services.paymentcryptography.model.Alias;
import com.amazonaws.services.paymentcryptography.model.ListAliasesRequest;
import com.amazonaws.services.paymentcryptography.model.ListAliasesResult;

public class ListAliases {

    public static void main(String[] args) {
        AWSPaymentCryptography client = ControlPlaneUtils.getControlPlaneClient();
        ListAliasesRequest request = new ListAliasesRequest().withMaxResults(2);
        ListAliasesResult result = client.listAliases(request);
        List<Alias> aliases = result.getAliases();
        while (null != aliases) {
            for (Alias alias : aliases) {
                System.out.println(String.format("%s : %s", alias.getAliasName(), alias.getKeyArn()));
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
}
