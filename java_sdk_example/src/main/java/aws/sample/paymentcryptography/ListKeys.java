package aws.sample.paymentcryptography;

import java.util.List;

import com.amazonaws.services.paymentcryptography.AWSPaymentCryptography;
import com.amazonaws.services.paymentcryptography.model.Key;
import com.amazonaws.services.paymentcryptography.model.KeyAttributes;
import com.amazonaws.services.paymentcryptography.model.KeySummary;
import com.amazonaws.services.paymentcryptography.model.ListKeysRequest;
import com.amazonaws.services.paymentcryptography.model.ListKeysResult;

public class ListKeys {

    public static void main(String[] args) {
        AWSPaymentCryptography client = ControlPlaneUtils.getControlPlaneClient();
        ListKeysRequest request = new ListKeysRequest().withMaxResults(2);
        ListKeysResult result = client.listKeys(request);
        List<KeySummary> keys = result.getKeys();
        while (null != keys) {
            for (KeySummary key : keys) {
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
