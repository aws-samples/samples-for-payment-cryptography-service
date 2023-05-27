package aws.example.magnus;

import com.amazonaws.services.magnuscontrolplane.model.Alias;
import com.amazonaws.services.magnuscontrolplane.model.Key;

import aws.example.magnus.ControlPlaneUtils;
import aws.example.magnus.DataPlaneUtils;

public class Demo {

    private static final String INPUT_PIN_BLOCK_FORMAT = "ISO_FORMAT_0";
    private static final String OUTPUT_PIN_BLOCK_FORMAT = "ISO_FORMAT_3";
    private static final String PRIMARY_ACCOUNT_NUMBER = "14123456789012";
    private static final String PRIMARY_ACCOUNT_NUMBER_2 = "14123456789000";
    private static final String OUTPUT_DUKPT_TYPE = "TDES_3KEY";
    private static final String OUTPUT_DUKPT_KSN = "1123456789ABCDEF1234";
    private static final int VERIFICATION_KEY_INDEX = 0;

    private static final String PEK_ALGO = "TDES_3KEY";
    private static final String BDK_ALGO = "AES_128";
    private static final String PGK_ALGO = "TDES_3KEY";

    public static void main(String[] args) {
        String aliasSuffix = "";
        if (args.length > 0) {
            aliasSuffix = args[0];
        }
        String pekAliasName = String.format("alias/demo-pek%s", aliasSuffix);
        String bdkAliasName = String.format("alias/demo-bdk%s", aliasSuffix);
        String pgkAliasName = String.format("alias/demo-pgk%s", aliasSuffix);
        Alias pekAlias = ControlPlaneUtils.getOrCreateAlias(pekAliasName);
        Alias bdkAlias = ControlPlaneUtils.getOrCreateAlias(bdkAliasName);
        Alias pgkAlias = ControlPlaneUtils.getOrCreateAlias(pgkAliasName);


        //finds or generates a Pin Generation Key (used for generating random PINs)
        if (null == pgkAlias.getKeyArn()) {
            System.out.println("No PGK found, creating a new one.");
            Key pgkKey = ControlPlaneUtils.createVisaPGK(PGK_ALGO);
            pgkAlias = ControlPlaneUtils.upsertAlias(pgkAliasName, pgkKey.getKeyArn());
            System.out.println(String.format("PGK created: %s", pgkAlias.getKeyArn()));
        } else {
            System.out.println(String.format("PGK already exists: %s", pgkAlias.getKeyArn()));
        }

        //finds existing or generates a Pin Encryption Key (used for encryption pin payloads)
        if (null == pekAlias.getKeyArn()) {
            System.out.println("No PEK found, creating a new one.");
            Key pekKey = ControlPlaneUtils.createPEK(PEK_ALGO);
            pekAlias = ControlPlaneUtils.upsertAlias(pekAliasName, pekKey.getKeyArn());
            System.out.println(String.format("PEK created: %s", pekAlias.getKeyArn()));
        } else {
            System.out.println(String.format("PEK already exists: %s", pekAlias.getKeyArn()));
        }

        //Generate a BDK used as the base deriviation key typically for DUKPT
        if (null == bdkAlias.getKeyArn()) {
            System.out.println("No BDK found, creating a new one.");
            Key bdkKey = ControlPlaneUtils.createBDK(BDK_ALGO);
            bdkAlias = ControlPlaneUtils.upsertAlias(bdkAliasName, bdkKey.getKeyArn());
            System.out.println(String.format("BDK created: %s", bdkAlias.getKeyArn()));
        } else {
            System.out.println(String.format("BDK already exists: %s", bdkAlias.getKeyArn()));
        }


        System.out.println("Creating a random pin and returns back the encrypted pin and visa/ABA PVV");
        String pinBlockUnderPEK = DataPlaneUtils.generateVisaPinBlock(
                                                             pekAliasName,
                                                             pgkAliasName,
                                                             INPUT_PIN_BLOCK_FORMAT,
                                                             PRIMARY_ACCOUNT_NUMBER,
                                                             VERIFICATION_KEY_INDEX
                                                             );
        System.out.println(String.format("PIN block: %s", pinBlockUnderPEK));


        System.out.println("Translating encrypted PIN under PEK to encrypted under DUKPT");
        String pinBlockUnderBDK = DataPlaneUtils.translateVisaPinBlockPekToBdk(
                                                                      pekAliasName,
                                                                      INPUT_PIN_BLOCK_FORMAT,
                                                                      pinBlockUnderPEK,
                                                                      bdkAliasName,
                                                                      OUTPUT_PIN_BLOCK_FORMAT,
                                                                      OUTPUT_DUKPT_TYPE,
                                                                      OUTPUT_DUKPT_KSN,
                                                                      PRIMARY_ACCOUNT_NUMBER
                                                                      );

        System.out.println(String.format("Translated PIN block: %s", pinBlockUnderBDK));
    }
}
