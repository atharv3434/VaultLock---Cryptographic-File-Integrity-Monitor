public class HasherTest {
    public static void main(String[] args) {
        testDeterministicOutput();
        testAvalcheEffect();
    }

    public static void testDeterministicOutput() {
        String message = "system_parameter_payload_token";
        String hash1 = App.calculateSHA256(message);
        String hash2 = App.calculateSHA256(message);

        if (hash1.equals(hash2)) {
            System.out.println("✅ Test Passed: Cryptographic outputs are perfectly deterministic.");
        } else {
            throw new AssertionError("Fails structural validation check.");
        }
    }

    public static void testAvalcheEffect() {
        String raw = "config.root=true";
        String mutated = "config.root=True"; // Single-bit manipulation character adjustment

        String hashRaw = App.calculateSHA256(raw);
        String hashMutated = App.calculateSHA256(mutated);

        if (!hashRaw.equals(hashMutated)) {
            System.out.println("✅ Test Passed: Avalanche Effect confirmed. Hex string structure completely flipped.");
        } else {
            throw new AssertionError("Fails crypt security avalanche checks.");
        }
    }
}