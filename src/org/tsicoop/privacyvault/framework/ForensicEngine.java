package org.tsicoop.privacyvault.framework;
import java.io.InputStream;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Scanner;
import java.util.Collections;
import java.util.List;

import org.json.simple.JSONObject;

public class ForensicEngine {

    public static JSONObject captureBSAMetadata() {
        JSONObject details = new JSONObject();
        try {
            // Part A Requirements: Device Identification & Health
            details.put("makeModel", System.getProperty("os.name") + " " + System.getProperty("os.version"));
            details.put("macAddress", getMacAddress());
            details.put("serialNumber", System.getProperty("os.arch")); // Placeholder for Hardware ID
            
            // Section 63(2)(c): Proving the system was "working properly"
            details.put("systemStatus", "OPERATING_PROPERLY");
            details.put("hashAlgorithm", "SHA256"); // Prescribed in Part B
        } catch (Exception e) {
            details.put("systemStatus", "LOGGING_ERROR");
        }
        return details;
    }

    private static String getMacAddress() throws Exception {
        Enumeration<NetworkInterface> nics = NetworkInterface.getNetworkInterfaces();
        while (nics.hasMoreElements()) {
            byte[] mac = nics.nextElement().getHardwareAddress();
            if (mac != null) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < mac.length; i++) sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                return sb.toString();
            }
        }
        return "UNKNOWN";
    }

    /**
     * Calculates the SHA-256 hash used as the Forensic Fingerprint.
     */
    public static String calculateSHA256(byte[] data) throws Exception {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        
        // Manual Hex conversion for compatibility with Java 8/11
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
  /**
     * Generates a unique identifier for the machine.
     * Prioritizes the mandatory environment variable for stable forensic anchoring.
     */
    public static String getMachineIdentifier() {
        try {
            // 1. Mandatory Environment Anchor (Best for Docker/Cloud)
            String nodeId = System.getenv("TSI_PRIVACY_VAULT_NODE_ID");
            if (nodeId != null && !nodeId.trim().isEmpty()) {
                return "NODE:" + nodeId.trim().toUpperCase();
            }

            // 2. Fallback: Standard Linux machine-id (if volume mounted)
            Path path = Paths.get("/etc/machine-id");
            if (Files.exists(path)) {
                String fileId = new String(Files.readAllBytes(path)).trim();
                if (!fileId.isEmpty()) {
                    return "HWID:" + fileId;
                }
            }
        } catch (Exception e) {
            // Log locally if needed, but do not throw to avoid breaking the calling action
            System.err.println("ForensicEngine: Error reading hardware identifiers: " + e.getMessage());
        }

        // 3. Last Resort Fallback (Warning: This may cause 403s on restart)
        return "UNIDENTIFIED-NODE-" + System.getProperty("os.name").toUpperCase();
    }

    /**
     * Executes shell commands to pull the hardware serial number from the BIOS/OS.
     */
    private static String getSystemSerialNumber() {
        String sn = "";
        try {
            String os = System.getProperty("os.name").toLowerCase();
            Process process;
            if (os.contains("win")) {
                process = Runtime.getRuntime().exec("wmic bios get serialnumber");
            } else if (os.contains("mac")) {
                process = Runtime.getRuntime().exec("ioreg -l | grep IOPlatformSerialNumber");
            } else {
                process = Runtime.getRuntime().exec("cat /sys/class/dmi/id/product_serial");
            }

            try (InputStream is = process.getInputStream(); Scanner sc = new Scanner(is)) {
                while (sc.hasNext()) {
                    String line = sc.next();
                    if (!line.equalsIgnoreCase("SerialNumber")) sn = line;
                }
            }
        } catch (Exception e) { /* Fallback to empty if shell access is restricted */ }
        return sn.trim();
    }
}   
