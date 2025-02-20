package aws.sample.paymentcryptography;

import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

import software.amazon.awssdk.services.paymentcryptography.PaymentCryptographyClient;
import software.amazon.awssdk.services.paymentcryptography.model.Alias;
import software.amazon.awssdk.services.paymentcryptography.model.ListAliasesRequest;

/* 
 * Usage - 
 * 
 * ./run_example.sh aws.sample.paymentcryptography.ListAliasesUtil
 * 
 */
 
public class ListAliasesUtil {

    public static void main(String[] args) throws InterruptedException, ExecutionException {
        PaymentCryptographyClient client = ControlPlaneUtils.getControlPlaneClient();
        ListAliasesRequest request = ListAliasesRequest.builder().build();
        List<Alias> aliases = client.listAliases(request).aliases();
        if (aliases.size() == 0) {
            Logger.getGlobal().log(Level.INFO,"No aliases found");
            return;
        }
        for (Alias alias : aliases) {
            Logger.getGlobal().log(Level.INFO,"{0} : {1}", new Object[] {alias.aliasName(), alias.keyArn()});
        }
    }
}
