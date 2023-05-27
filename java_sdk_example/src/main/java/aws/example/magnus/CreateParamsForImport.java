package aws.example.magnus;

import com.amazonaws.services.magnuscontrolplane.model.Alias;
import com.amazonaws.services.magnuscontrolplane.model.GetParametersForImportResult;

public class CreateParamsForImport {

    public static void main(String[] args) {

        GetParametersForImportResult result = ControlPlaneUtils.getImportKeyParams();
        System.out.println(String.format("Import Token: %s", result.getImportToken()));

        System.out.println(String.format("Wrapping Certificate: %s", result.getWrappingKeyCertificate()));
        System.out.println(String.format("Wrapping Certificate: %s", result.getWrappingKeyCertificateChain()));

    }
}
