package org.tsicoop.privacyvault.framework;

import java.io.InputStream;
import java.util.Properties;

/**
 * Build metadata. The version comes from pom.xml through the filtered version.properties,
 * so it cannot drift from the artifact that is actually running.
 */
public final class BuildInfo {

    private static final String VERSION = load();

    private BuildInfo() { }

    public static String version() {
        return VERSION;
    }

    private static String load() {
        try (InputStream in = BuildInfo.class.getResourceAsStream("/version.properties")) {
            if (in != null) {
                Properties p = new Properties();
                p.load(in);
                String v = p.getProperty("version");
                // An unfiltered file still holds the literal placeholder.
                if (v != null && !v.trim().isEmpty() && !v.contains("${")) return v.trim();
            }
        } catch (Exception ignored) {
            // fall through
        }
        return "unknown";
    }
}
