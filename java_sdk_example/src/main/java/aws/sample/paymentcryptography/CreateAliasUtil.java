package aws.sample.paymentcryptography;

import java.util.concurrent.ExecutionException;

import software.amazon.awssdk.services.paymentcryptography.model.Alias;

public class CreateAliasUtil {

    public static void main(String[] args) throws InterruptedException, ExecutionException {
        String aliasName = String.format("alias/createalias-%d", System.currentTimeMillis());
        if (args.length > 0) {
            aliasName = args[0];
        }
        Alias alias = ControlPlaneUtils.getOrCreateAlias(aliasName);
        System.out.println(String.format("Alias name: %s", alias.aliasName()));
        System.out.println(String.format("Key ARN: %s", alias.keyArn()));
    }
}
