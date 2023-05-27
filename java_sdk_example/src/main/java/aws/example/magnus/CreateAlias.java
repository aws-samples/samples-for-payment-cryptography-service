package aws.example.magnus;

import com.amazonaws.services.magnuscontrolplane.model.Alias;

import aws.example.magnus.ControlPlaneUtils;

public class CreateAlias {

    public static void main(String[] args) {
        String aliasName = String.format("alias/createalias-%d", System.currentTimeMillis());
        if (args.length > 0) {
            aliasName = args[0];
        }
        Alias alias = ControlPlaneUtils.getOrCreateAlias(aliasName);
        System.out.println(String.format("Alias name: %s", alias.getAliasName()));
        System.out.println(String.format("Key ARN: %s", alias.getKeyArn()));
    }
}
