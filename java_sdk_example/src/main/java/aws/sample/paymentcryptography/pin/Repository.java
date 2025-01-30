package aws.sample.paymentcryptography.pin;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.springframework.stereotype.Component;

@Component
public class Repository {

    private static final String PAN_TO_PVV_FILE = System.getProperty("user.dir")
            + "/test-data/pan_to_pin_verification.csv";
    private File panToPinVerificationValueMapFile = new File(PAN_TO_PVV_FILE);
    private BufferedWriter writer = null;
    private Map<String, String> panToPvvMap = null;

    public Repository() throws Exception {
        if (!getPanToPinVerificationValueMapFile().exists()) {
            Logger.getGlobal().log(Level.INFO,"Creating new pan to pin verification map file {0} ", getPanToPinVerificationValueMapFile().getAbsoluteFile());
            try {
                panToPinVerificationValueMapFile.createNewFile();
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }
        //panToPvvMap = getMapFromCSV(getPanToPinVerificationValueMapFile().getAbsolutePath());
        setWriter(new BufferedWriter(new FileWriter(getPanToPinVerificationValueMapFile())));
    }

    private Map<String, String> getMapFromCSV(final String filePath) throws Exception {
            Map<String, String> map = new HashMap<String, String>();
            BufferedReader bufferedReader = null;
            try {
                bufferedReader = new BufferedReader(new FileReader(getPanToPinVerificationValueMapFile()));
                String line = null;
                // read file line by line
                while ((line = bufferedReader.readLine()) != null && line.trim() !="") {
                    map.put(line.split(",")[0], line.split(",")[1]);
                }
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if(bufferedReader!=null) 
                    bufferedReader.close();
            }
            return map;
    }

    public void addEntry(String pan, String pinVerificationValue) throws IOException {
        getWriter().append(pan + "," + pinVerificationValue);
        writer.newLine();
        getWriter().flush();
    }

    public String getEntry(String pan) throws Exception {
        setPanToPvvMap(getMapFromCSV(PAN_TO_PVV_FILE));
        return getPanToPvvMap().get(pan);
    }

    private File getPanToPinVerificationValueMapFile() {
        return panToPinVerificationValueMapFile;
    }

    private void setWriter(BufferedWriter writer) {
        this.writer = writer;
    }

    private BufferedWriter getWriter() {
        return writer;
    }

    public Map<String, String> getPanToPvvMap() {
        return panToPvvMap;
    }

    public void setPanToPvvMap(Map<String, String> panToPvvMap) {
        this.panToPvvMap = panToPvvMap;
    }

}
