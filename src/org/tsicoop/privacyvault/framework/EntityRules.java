package org.tsicoop.privacyvault.framework;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Validation rules for entity definitions (admin side) and for values stored against
 * an entity (data plane). Everything here fails closed: unknown content types are rejected.
 */
public final class EntityRules {

    public static final int DEFAULT_MAX_UPLOAD_KB = 5120;

    private static final int MAX_NAME_LENGTH = 255;
    private static final int MAX_REGEX_LENGTH = 500;
    private static final int MAX_MIME_ENTRIES = 20;
    private static final int MAX_FILE_NAME_LENGTH = 255;
    private static final int REGEX_STEP_BUDGET = 2_000_000;

    private static final Pattern ENTITY_CODE = Pattern.compile("^[A-Za-z0-9_-]{1,50}$");
    private static final Pattern MIME_TYPE = Pattern.compile(
            "^[a-z0-9][a-z0-9!#$&^_.+-]*/([a-z0-9][a-z0-9!#$&^_.+-]*|\\*)$");
    private static final Set<String> FLAVORS = new LinkedHashSet<>(Arrays.asList("ID", "DATA", "FILE"));

    private static final String ZIP = "application/zip";
    private static final String TEXT = "text/plain";
    private static final String DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    private static final String XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    private static final String PPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation";

    /** Extension to the one content type its bytes must sniff as. */
    private static final Map<String, String> STRICT_EXT = new HashMap<>();
    /** Extensions whose bytes sniff as a generic container (zip) and need an allow-list match. */
    private static final Map<String, String> ZIP_EXT = new HashMap<>();
    /** Extensions whose bytes sniff as generic text. */
    private static final Map<String, String> TEXT_EXT = new HashMap<>();

    static {
        STRICT_EXT.put("pdf", "application/pdf");
        STRICT_EXT.put("png", "image/png");
        STRICT_EXT.put("jpg", "image/jpeg");
        STRICT_EXT.put("jpeg", "image/jpeg");
        STRICT_EXT.put("gif", "image/gif");
        ZIP_EXT.put("docx", DOCX);
        ZIP_EXT.put("xlsx", XLSX);
        ZIP_EXT.put("pptx", PPTX);
        ZIP_EXT.put("zip", ZIP);
        TEXT_EXT.put("txt", TEXT);
        TEXT_EXT.put("csv", "text/csv");
        TEXT_EXT.put("json", "application/json");
        TEXT_EXT.put("xml", "application/xml");
    }

    private EntityRules() {}

    // ------------------------------------------------------------------
    // Entity definition (admin)
    // ------------------------------------------------------------------

    /** Result of normalizing an entity definition. {@code error} is null when valid. */
    public static final class Definition {
        public String error;
        public String flavor;
        public String validationRegex;
        public String mimeTypes;
        public Integer maxSizeKb;
    }

    /**
     * Validates and normalizes an entity definition. Pass {@code checkCode = true} on create.
     * The returned definition holds the values that should be persisted.
     */
    public static Definition validateDefinition(String entityCode, String entityName, String flavor,
                                                String regex, String mimeTypes, Integer maxSizeKb,
                                                boolean checkCode) {
        Definition d = new Definition();

        if (checkCode && (entityCode == null || !ENTITY_CODE.matcher(entityCode).matches())) {
            d.error = "entity_code must be 1 to 50 characters: letters, digits, underscore or hyphen.";
            return d;
        }
        if (entityName == null || entityName.trim().isEmpty() || entityName.length() > MAX_NAME_LENGTH) {
            d.error = "entity_name is required and must be at most " + MAX_NAME_LENGTH + " characters.";
            return d;
        }
        String f = flavor == null ? "" : flavor.trim().toUpperCase(Locale.ROOT);
        if (!FLAVORS.contains(f)) {
            d.error = "flavor must be one of ID, DATA or FILE.";
            return d;
        }
        d.flavor = f;

        String rx = blankToNull(regex);
        String mt = blankToNull(mimeTypes);

        if ("FILE".equals(f)) {
            if (rx != null) {
                d.error = "validation_regex applies to ID and DATA entities only.";
                return d;
            }
            if (mt == null) {
                d.error = "mime_types is required for FILE entities.";
                return d;
            }
            String normalized = normalizeMimeTypes(mt);
            if (normalized == null) {
                d.error = "mime_types must be a comma separated list of type/subtype values "
                        + "(for example application/pdf, image/*), at most " + MAX_MIME_ENTRIES + " entries.";
                return d;
            }
            d.mimeTypes = normalized;
        } else {
            if (mt != null) {
                d.error = "mime_types applies to FILE entities only.";
                return d;
            }
            if (rx != null) {
                if (rx.length() > MAX_REGEX_LENGTH) {
                    d.error = "validation_regex must be at most " + MAX_REGEX_LENGTH + " characters.";
                    return d;
                }
                try {
                    Pattern.compile(rx);
                } catch (PatternSyntaxException e) {
                    d.error = "validation_regex is not a valid regular expression: " + e.getDescription();
                    return d;
                }
            }
            d.validationRegex = rx;
        }

        if (maxSizeKb != null) {
            if (maxSizeKb < 1) {
                d.error = "max_size_kb must be a positive number.";
                return d;
            }
            d.maxSizeKb = maxSizeKb;
        }
        return d;
    }

    private static String blankToNull(String s) {
        return (s == null || s.trim().isEmpty()) ? null : s.trim();
    }

    /** Returns the lower-cased, de-duplicated list joined by commas, or null if invalid. */
    static String normalizeMimeTypes(String raw) {
        Set<String> out = new LinkedHashSet<>();
        for (String part : raw.split(",")) {
            String t = part.trim().toLowerCase(Locale.ROOT);
            if (t.isEmpty()) continue;
            if (!MIME_TYPE.matcher(t).matches()) return null;
            out.add(t);
        }
        if (out.isEmpty() || out.size() > MAX_MIME_ENTRIES) return null;
        return String.join(",", out);
    }

    // ------------------------------------------------------------------
    // Size limits
    // ------------------------------------------------------------------

    /** System-wide upload cap in KB from the environment, falling back to 5120. */
    public static long systemMaxUploadKb() {
        String v = System.getenv("TSI_PRIVACY_VAULT_MAX_UPLOAD_KB");
        if (v == null || v.trim().isEmpty()) v = System.getenv("VAULT_MAX_UPLOAD_KB"); // legacy name
        if (v != null) {
            try {
                long kb = Long.parseLong(v.trim());
                if (kb > 0) return kb;
            } catch (NumberFormatException ignored) {
                // fall through to the default
            }
        }
        return DEFAULT_MAX_UPLOAD_KB;
    }

    /** The lower of the system cap and the entity's own limit, in KB. */
    public static long effectiveMaxKb(Integer entityMaxKb) {
        long sys = systemMaxUploadKb();
        return (entityMaxKb != null && entityMaxKb > 0) ? Math.min(sys, entityMaxKb) : sys;
    }

    // ------------------------------------------------------------------
    // Values (data plane)
    // ------------------------------------------------------------------

    /**
     * Returns null when {@code text} fully matches {@code regex} (or when no regex is set),
     * otherwise an error message. Matching is bounded so a hostile pattern cannot hang a thread.
     */
    public static String checkValue(String regex, String text) {
        if (regex == null || regex.isEmpty()) return null;
        try {
            Pattern p = Pattern.compile(regex);
            return p.matcher(new BoundedCharSequence(text, REGEX_STEP_BUDGET)).matches()
                    ? null
                    : "Value does not match the format required for this entity.";
        } catch (PatternSyntaxException e) {
            return "Entity validation rule is invalid. Contact an administrator.";
        } catch (IllegalStateException e) {
            return "Value could not be validated within the allowed effort.";
        }
    }

    /**
     * Strips any path, replaces unsafe characters and limits the length. Returns null when no
     * usable name remains.
     */
    public static String sanitizeFileName(String name) {
        if (name == null) return null;
        String base = name;
        int slash = Math.max(base.lastIndexOf('/'), base.lastIndexOf('\\'));
        if (slash >= 0) base = base.substring(slash + 1);
        base = base.replaceAll("[^\\p{L}\\p{N}._ ()\\-]", "_").trim();
        if (base.length() > MAX_FILE_NAME_LENGTH) base = base.substring(base.length() - MAX_FILE_NAME_LENGTH);
        if (base.isEmpty() || base.equals(".") || base.equals("..")) return null;
        return base;
    }

    /**
     * Checks file bytes against the entity's allowed types. Returns null when allowed,
     * otherwise an error message.
     */
    public static String checkFile(byte[] bytes, String fileName, String allowedMimeTypes) {
        if (allowedMimeTypes == null || allowedMimeTypes.trim().isEmpty()) {
            return "This FILE entity has no accepted MIME types configured.";
        }
        if (bytes == null || bytes.length == 0) return "File is empty.";

        String sniffed = sniff(bytes);
        if (sniffed == null) return "File content type could not be identified or is not supported.";

        String ext = extensionOf(fileName);
        String strict = ext == null ? null : STRICT_EXT.get(ext);
        if (strict != null && !strict.equals(sniffed)) {
            return "File content does not match its ." + ext + " extension.";
        }

        Set<String> candidates = new LinkedHashSet<>();
        candidates.add(sniffed);
        if (ZIP.equals(sniffed) && ext != null && ZIP_EXT.containsKey(ext)) candidates.add(ZIP_EXT.get(ext));
        if (TEXT.equals(sniffed) && ext != null && TEXT_EXT.containsKey(ext)) candidates.add(TEXT_EXT.get(ext));

        List<String> allowed = new ArrayList<>(Arrays.asList(allowedMimeTypes.toLowerCase(Locale.ROOT).split(",")));
        for (String c : candidates) {
            for (String a : allowed) {
                String rule = a.trim();
                if (rule.equals(c)) return null;
                if (rule.endsWith("/*") && c.startsWith(rule.substring(0, rule.length() - 1))) return null;
            }
        }
        return "File type " + candidates.iterator().next() + " is not accepted for this entity.";
    }

    private static String extensionOf(String fileName) {
        if (fileName == null) return null;
        int dot = fileName.lastIndexOf('.');
        if (dot < 0 || dot == fileName.length() - 1) return null;
        return fileName.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    /** Identifies a small set of types by magic number. Returns null for anything else. */
    static String sniff(byte[] b) {
        if (startsWith(b, '%', 'P', 'D', 'F', '-')) return "application/pdf";
        if (startsWith(b, 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A)) return "image/png";
        if (startsWith(b, 0xFF, 0xD8, 0xFF)) return "image/jpeg";
        if (startsWith(b, 'G', 'I', 'F', '8', '7', 'a') || startsWith(b, 'G', 'I', 'F', '8', '9', 'a')) return "image/gif";
        if (startsWith(b, 'P', 'K', 0x03, 0x04)) return ZIP;
        if (isPlainText(b)) return TEXT;
        return null;
    }

    private static boolean startsWith(byte[] b, int... magic) {
        if (b.length < magic.length) return false;
        for (int i = 0; i < magic.length; i++) {
            if ((b[i] & 0xFF) != magic[i]) return false;
        }
        return true;
    }

    private static boolean isPlainText(byte[] b) {
        int start = (b.length >= 3 && (b[0] & 0xFF) == 0xEF && (b[1] & 0xFF) == 0xBB && (b[2] & 0xFF) == 0xBF) ? 3 : 0;
        for (int i = start; i < b.length; i++) {
            int c = b[i] & 0xFF;
            if (c == 0 || (c < 0x20 && c != '\t' && c != '\n' && c != '\r')) return false;
        }
        return decodeUtf8(b) != null;
    }

    /** Strict UTF-8 decode. Returns null when the bytes are not valid UTF-8. */
    public static String decodeUtf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    /** A CharSequence that throws once too many characters have been read. */
    private static final class BoundedCharSequence implements CharSequence {
        private final CharSequence inner;
        private final int[] budget;

        BoundedCharSequence(CharSequence inner, int budget) {
            this(inner, new int[] { budget });
        }

        private BoundedCharSequence(CharSequence inner, int[] budget) {
            this.inner = inner;
            this.budget = budget;
        }

        @Override public char charAt(int index) {
            if (--budget[0] < 0) throw new IllegalStateException("regex budget exceeded");
            return inner.charAt(index);
        }
        @Override public int length() { return inner.length(); }
        @Override public CharSequence subSequence(int start, int end) {
            return new BoundedCharSequence(inner.subSequence(start, end), budget);
        }
        @Override public String toString() { return inner.toString(); }
    }
}
