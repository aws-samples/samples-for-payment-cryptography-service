package aws.sample.paymentcryptography;

import org.json.JSONObject;
import software.amazon.awssdk.services.paymentcryptographydata.PaymentCryptographyDataClient;
import software.amazon.awssdk.services.paymentcryptographydata.model.*;

import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.math.BigInteger;

public class EncryptionUtil {

    //Decryption API example
    public String decrypt(String encryptedData, String ksn, String bdkAlias) {//print all arguments
        Logger.getGlobal().log(Level.INFO,
                "EncryptionUtil:decrypt Request received with encryptedData {0}, ksn {1}, bdkAlias{2}",
                new Object[] {encryptedData, ksn, bdkAlias});

        try {
            PaymentCryptographyDataClient dataPlaneClient = DataPlaneUtils.getDataPlaneClient();

            DukptEncryptionAttributes dukptEncryptionAttributes = DukptEncryptionAttributes
                    .builder()
                    .keySerialNumber(ksn)
                    .mode(ServiceConstants.MODE)
                    .build();

            EncryptionDecryptionAttributes decryptionAttributes = EncryptionDecryptionAttributes
                    .builder()
                    .dukpt(dukptEncryptionAttributes)
                    .build();

            DecryptDataRequest decryptDataRequest = DecryptDataRequest
                    .builder()
                    .cipherText(encryptedData)
                    .keyIdentifier(bdkAlias)
                    .decryptionAttributes(decryptionAttributes)
                    .build();

            Logger.getGlobal()
                    .log(Level.INFO,"Attempting to decrypt data {0}" ,encryptedData);
            DecryptDataResponse decryptDataResponse = dataPlaneClient.decryptData(decryptDataRequest);

            Logger.getGlobal()
                    .log(Level.INFO,"Decrypted data {0}" ,decryptDataResponse.plainText());

            return decryptDataResponse.plainText();

        } catch (Exception exception) {
            Logger.getGlobal().log(Level.INFO,
                    "Decrypted: Error occurred when decrypting");
            JSONObject returnJsonObject = new JSONObject()
                    .put("response", exception.getMessage());
            exception.printStackTrace();
            return returnJsonObject.toString();
        }
    }

    //Encryption API example
    public String encrypt(String track2Data, String ksn, String bdkAlias) {
        Logger.getGlobal().log(Level.INFO,
                "EncryptionUtil:encrypt Request received with track2Data {0}, ksn {1}, bdkAlias{2}",
                new Object[] {track2Data, ksn, bdkAlias});

        try {
            PaymentCryptographyDataClient dataPlaneClient = DataPlaneUtils.getDataPlaneClient();

            DukptEncryptionAttributes dukptEncryptionAttributes = DukptEncryptionAttributes
                    .builder()
                    .keySerialNumber(ksn)
                    .mode(ServiceConstants.MODE)
                    .build();

            EncryptionDecryptionAttributes encryptionAttributes = EncryptionDecryptionAttributes
                    .builder()
                    .dukpt(dukptEncryptionAttributes)
                    .build();

            EncryptDataRequest  encryptDataRequest = EncryptDataRequest
                    .builder()
                    .plainText(track2Data)
                    .keyIdentifier(bdkAlias)
                    .encryptionAttributes(encryptionAttributes)
                    .build();

            String encryptedData = dataPlaneClient.encryptData(encryptDataRequest).cipherText();

            Logger.getGlobal()
                    .log(Level.INFO, "Encrypted data {0}", encryptedData);

            return encryptedData;

        } catch (Exception exception) {
            Logger.getGlobal().log(Level.INFO,
                    "Encrypted: Error occurred when encrypting");
            JSONObject returnJsonObject = new JSONObject()
                    .put("response", exception.getMessage());
            exception.printStackTrace();
            return returnJsonObject.toString();
        }
    }
    public static void main(String[] args) {

        EncryptionUtil encryptionUtil = new EncryptionUtil();
        String ksn = "064E7913030373800000";
        String encryptedData = "1AA20535832C1E1517C39D09865B6EBB";
        String bdkAlias = ServiceConstants.BDK_ALIAS_TDES_2KEY;
        String decryptedData = encryptionUtil.decrypt(encryptedData, ksn, bdkAlias);
        System.out.println(decryptedData);
        Logger.getGlobal().log(Level.INFO,
                "EncryptionUtil:Decrypted data is {0}",
                new Object[] {decryptedData});
    }

    protected static String getRandomNumberWithDigitCount(int digCount) {
        Random rnd = new Random();
        StringBuilder sb = new StringBuilder(digCount);
        for (int i = 0; i < digCount; i++)
            sb.append((char) ('0' + rnd.nextInt(10)));
        return sb.toString();
    }
}
