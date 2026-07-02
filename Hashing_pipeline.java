import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class HashingPipeline {

    public static String executeSHA256(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Running Java Content Verification Steps...");
        String baseData = "system_config_allow_root=true";
        String mutatedData = "system_config_allow_root=false";

        System.out.println("Base Fingerprint String:    " + executeSHA256(baseData));
        System.out.println("Mutated Fingerprint String: " + executeSHA256(mutatedData));
    }
}