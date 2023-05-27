package aws.example.magnus;

import aws.example.magnus.ControlPlaneUtils;
import com.amazonaws.services.magnuscontrolplane.AWSMagnusControlPlane;
import com.amazonaws.services.magnuscontrolplane.model.Key;
import com.amazonaws.services.magnuscontrolplane.model.KeyAttributes;
import com.amazonaws.services.magnuscontrolplane.model.ListKeysRequest;
import com.amazonaws.services.magnuscontrolplane.model.ListKeysResult;

import java.util.List;

public class ListKeys {

    public static void main(String[] args) {
        AWSMagnusControlPlane client = ControlPlaneUtils.getControlPlaneClient();
        ListKeysRequest request = new ListKeysRequest().withMaxResults(2);
        ListKeysResult result = client.listKeys(request);
        List<Key> keys = result.getKeys();
        while (null != keys) {
            for (Key key : keys) {
                Key fullKey = ControlPlaneUtils.getKey(key.getKeyArn());
                KeyAttributes attrs = fullKey.getKeyAttributes();
                System.out.println(String.format(
                                                 "%s (%s / %s / %s)",
                                                 key.getKeyArn(),
                                                 attrs.getKeyClass(),
                                                 attrs.getKeyAlgorithm(),
                                                 attrs.getKeyUsage())
                                   );
            }
            if (null != result.getNextToken()) {
                System.out.println("Requesting another page of keys...");
                result = client.listKeys(request.withNextToken(result.getNextToken()));
                keys = result.getKeys();
            } else {
                System.out.println("Reached the last page of keys.");
                keys = null;
            }
        }
    }
}
