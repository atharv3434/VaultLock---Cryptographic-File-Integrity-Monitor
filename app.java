import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.time.Instant;
import java.util.UUID;

public class App {
    private static final String DB_URL = "jdbc:sqlite:integrity_audit.db";

    public static void main(String[] args) throws Exception {
        initDatabase();
        
        // Boot embedded HTTP server on port 8000
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        
        // Bind endpoint routes with manual CORS capability mapping
        server.createContext("/integrity/register", new RegisterHandler());
        server.createContext("/integrity/verify", new VerifyHandler());
        server.createContext("/integrity/ledger", new LedgerHandler());
        
        server.setExecutor(null); // default executor
        System.out.println("⚡ VoltLock Java Hashing Engine active on port 8000...");
        server.start();
    }

    private static void initDatabase() {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement()) {
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS snapshot_ledger (
                    record_id TEXT PRIMARY KEY,
                    file_name TEXT,
                    content_hash TEXT,
                    security_verdict TEXT,
                    last_checked TEXT
                )
            """);
        } catch (SQLException e) {
            System.err.println("Database DDL initialization failed: " + e.getMessage());
        }
    }

    // ── CRYPTOGRAPHIC SHA-256 EXTRACTION ENGINE ─────────────────────────────
    public static String calculateSHA256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm instance not found", e);
        }
    }

    // ── HTTP ROUTE HANDLERS (WITH NATIVE CORS SEPARATION) ───────────────────
    static class RegisterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            enableCORS(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                // Simple regex token parser substituting robust JSON frameworks
                String fileName = parseJsonField(body, "file_name");
                String fileContents = parseJsonField(body, "file_contents");

                String calculatedHash = calculateSHA256(fileContents);
                String recordId = "REC-" + UUID.randomUUID().toString().substring(0, 6).toUpperCase();
                String timestamp = Instant.now().toString();

                try (Connection conn = DriverManager.getConnection(DB_URL);
                     PreparedStatement pstmt = conn.prepareStatement(
                             "INSERT OR REPLACE INTO snapshot_ledger VALUES (?, ?, ?, ?, ?)")) {
                    pstmt.setString(1, recordId);
                    pstmt.setString(2, fileName);
                    pstmt.setString(3, calculatedHash);
                    pstmt.setString(4, "SAFE");
                    pstmt.setString(5, timestamp);
                    pstmt.executeUpdate();
                } catch (SQLException e) {
                    sendResponse(exchange, 500, "{\"error\":\"Database registration failed\"}");
                    return;
                }

                String jsonResponse = String.format(
                    "{\"status\":\"Baseline Registered\",\"file\":\"%s\",\"sha256_hash\":\"%s\"}",
                    fileName, calculatedHash
                );
                sendResponse(exchange, 200, jsonResponse);
            }
        }
    }

    static class VerifyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            enableCORS(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String fileName = parseJsonField(body, "file_name");
                String fileContents = parseJsonField(body, "file_contents");

                String currentHash = calculateSHA256(fileContents);
                String baselineHash = "";

                try (Connection conn = DriverManager.getConnection(DB_URL)) {
                    PreparedStatement selectStmt = conn.prepareStatement(
                            "SELECT content_hash FROM snapshot_ledger WHERE file_name = ? ORDER BY last_checked DESC LIMIT 1");
                    selectStmt.setString(1, fileName);
                    ResultSet rs = selectStmt.executeQuery();
                    
                    if (!rs.next()) {
                        sendResponse(exchange, 404, "{\"error\":\"File tracking baseline missing from profiles.\"}");
                        return;
                    }
                    baselineHash = rs.getString("content_hash");

                    // Avalanche effect verification comparison logic
                    String verdict = currentHash.equals(baselineHash) ? "SAFE" : "TAMPERED_ALERT";
                    String recordId = "REC-" + UUID.randomUUID().toString().substring(0, 6).toUpperCase();
                    String timestamp = Instant.now().toString();

                    PreInsertLog(conn, recordId, fileName, currentHash, verdict, timestamp);

                    String jsonResponse = String.format(
                        "{\"verdict\":\"%s\",\"baseline_registered_hash\":\"%s\",\"current_extracted_hash\":\"%s\",\"checked_at\":\"%s\"}",
                        verdict, baselineHash, currentHash, timestamp
                    );
                    sendResponse(exchange, 200, jsonResponse);
                } catch (SQLException e) {
                    sendResponse(exchange, 500, "{\"error\":\"Integrity verification cycle broken\"}");
                }
            }
        }
    }

    static class LedgerHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            enableCORS(exchange);
            if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                StringBuilder jsonBuilder = new StringBuilder("[");
                try (Connection conn = DriverManager.getConnection(DB_URL);
                     Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery("SELECT * FROM snapshot_ledger ORDER BY last_checked DESC LIMIT 15")) {
                    
                    boolean first = true;
                    while (rs.next()) {
                        if (!first) jsonBuilder.append(",");
                        jsonBuilder.append(String.format(
                            "{\"record_id\":\"%s\",\"file_name\":\"%s\",\"content_hash\":\"%s\",\"verdict\":\"%s\",\"last_checked\":\"%s\"}",
                            rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5)
                        ));
                        first = false;
                    }
                } catch (SQLException e) {
                    sendResponse(exchange, 500, "{\"error\":\"Ledger query failure\"}");
                    return;
                }
                jsonBuilder.append("]");
                sendResponse(exchange, 200, jsonBuilder.toString());
            }
        }
    }

    // ── SHARED ARCHITECTURAL UTILITIES ───────────────────────────────────────
    private static void PreInsertLog(Connection conn, String rid, String fName, String hash, String vrd, String ts) throws SQLException {
        try (PreparedStatement insertStmt = conn.prepareStatement("INSERT INTO snapshot_ledger VALUES (?, ?, ?, ?, ?)")) {
            insertStmt.setString(1, rid);
            insertStmt.setString(2, fName);
            insertStmt.setString(3, hash);
            insertStmt.setString(4, vrd);
            insertStmt.setString(5, ts);
            insertStmt.executeUpdate();
        }
    }

    private static void enableCORS(HttpExchange exchange) {
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type,Authorization");
    }

    private static void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String parseJsonField(String json, String fieldName) {
        String pattern = "\"" + fieldName + "\"\\s*:\\s*\"(([^\"]|\\\")*)\"";
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(pattern).matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }
}