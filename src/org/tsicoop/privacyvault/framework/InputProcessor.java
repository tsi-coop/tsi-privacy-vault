package org.tsicoop.privacyvault.framework;

import com.networknt.schema.ValidationMessage;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Set;
import java.util.StringTokenizer;

public class InputProcessor {
    public final static String REQUEST_DATA = "input_json";
    public final static String AUTH_TOKEN = "auth_token";
    public final static String CONSOLE_SESSION_COOKIE = "console_session";
    private final static int CONSOLE_SESSION_MAX_AGE_SECONDS = 864000; // matches JWT lifetime (10 days)

    /**
     * Sets the HttpOnly console session cookie read by ConsoleAuthFilter. Built as a raw
     * Set-Cookie header because the Servlet 5.0 Cookie API has no SameSite support.
     * Secure is omitted only when TSI_PRIVACY_VAULT_ENV=local so plain-http local dev works.
     */
    public static void setConsoleSessionCookie(HttpServletResponse res, String token) {
        StringBuilder cookie = new StringBuilder();
        cookie.append(CONSOLE_SESSION_COOKIE).append('=').append(token)
                .append("; Path=/; Max-Age=").append(CONSOLE_SESSION_MAX_AGE_SECONDS)
                .append("; HttpOnly; SameSite=Strict");
        if (!"local".equals(System.getenv("TSI_PRIVACY_VAULT_ENV"))) cookie.append("; Secure");
        res.addHeader("Set-Cookie", cookie.toString());
    }

    /** Expires the console session cookie. Used on logout. */
    public static void clearConsoleSessionCookie(HttpServletResponse res) {
        StringBuilder cookie = new StringBuilder();
        cookie.append(CONSOLE_SESSION_COOKIE).append("=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
        if (!"local".equals(System.getenv("TSI_PRIVACY_VAULT_ENV"))) cookie.append("; Secure");
        res.addHeader("Set-Cookie", cookie.toString());
    }

    public static void processInput(HttpServletRequest request, HttpServletResponse response){
        String contentType = request.getContentType();
        StringBuilder buffer = new StringBuilder();
        try {
            BufferedReader reader = request.getReader();
            String line = null;
            while ((line = reader.readLine()) != null) {
                //System.out.println("line"+line);
                buffer.append(line);
                buffer.append(System.lineSeparator());
            }
            String data = buffer.toString();
            //System.out.println(data);
            request.setAttribute(REQUEST_DATA, data);
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static boolean processAdminHeader(HttpServletRequest request, HttpServletResponse response) {
        boolean validheader = false;
        JSONObject authToken = null;
        try {
            authToken = getAdminAuthToken(request, response);
            if(authToken != null) {
                request.setAttribute(AUTH_TOKEN, authToken);
                validheader = true;
            }
        }catch (Exception e){}
        return validheader;
    }

    // PBKDF2 (65536 iterations) is deliberately slow, so a successful secret verification is
    // cached briefly. The key's active flag and stored hash are re-read from the database on
    // every request, so deactivating a key or rotating its secret takes effect immediately.
    private static final long SECRET_CACHE_TTL_MS = 60_000L;
    private static final int SECRET_CACHE_MAX_ENTRIES = 5_000;
    private static final java.util.concurrent.ConcurrentHashMap<String, Long> verifiedSecrets =
            new java.util.concurrent.ConcurrentHashMap<>();

    /**
     * Authenticates a data-plane client: the X-API-Key must exist and be active, and the
     * X-API-Secret must match the PBKDF2 hash stored for it at key creation.
     */
    public static boolean processClientHeader(HttpServletRequest req, HttpServletResponse res) {
        String apiKey = req.getHeader("X-API-Key");
        String apiSecret = req.getHeader("X-API-Secret");
        if (apiKey == null || apiKey.trim().isEmpty()) return false;
        if (apiSecret == null || apiSecret.isEmpty()) return false;

        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = null;

        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT active, api_secret FROM api_user WHERE api_key = ?");
            ps.setString(1, apiKey);
            rs = ps.executeQuery();

            if (rs.next()) {
                if (!rs.getBoolean("active")) return false;
                return secretMatches(apiKey, apiSecret, rs.getString("api_secret"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (pool != null) pool.cleanup(rs, ps, conn);
        }
        return false; // Key does not exist
    }

    /** Verifies a raw secret against a stored "iterations:salt_b64:hash_b64" PBKDF2 value. */
    private static boolean secretMatches(String apiKey, String rawSecret, String stored) {
        if (stored == null) return false;
        try {
            // The cache key binds the key, the presented secret and the stored hash, so a
            // rotated secret (new stored hash) never matches an old cache entry.
            java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-256");
            byte[] digest = sha.digest((apiKey + "\u0000" + rawSecret + "\u0000" + stored)
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String cacheKey = java.util.Base64.getEncoder().encodeToString(digest);

            Long expiresAt = verifiedSecrets.get(cacheKey);
            long now = System.currentTimeMillis();
            if (expiresAt != null && expiresAt > now) return true;

            String[] parts = stored.split(":");
            if (parts.length != 3) return false;
            int iterations = Integer.parseInt(parts[0]);
            byte[] salt = java.util.Base64.getDecoder().decode(parts[1]);
            byte[] expected = java.util.Base64.getDecoder().decode(parts[2]);

            javax.crypto.SecretKeyFactory factory =
                    javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] actual = factory.generateSecret(new javax.crypto.spec.PBEKeySpec(
                    rawSecret.toCharArray(), salt, iterations, expected.length * 8)).getEncoded();

            boolean ok = java.security.MessageDigest.isEqual(expected, actual);
            if (ok) {
                if (verifiedSecrets.size() >= SECRET_CACHE_MAX_ENTRIES) verifiedSecrets.clear();
                verifiedSecrets.put(cacheKey, now + SECRET_CACHE_TTL_MS);
            }
            return ok;
        } catch (Exception e) {
            return false;
        }
    }

    public static String getEmail(HttpServletRequest req){
        JSONObject authToken = null;
        String email = null;
        try {
            authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
            email = (String) authToken.get("email");
        }catch(Exception e){
            e.printStackTrace();
        }
        return email;
    }

    public static String getName(HttpServletRequest req){
        JSONObject authToken = null;
        String name = null;
        try {
            authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
            name = (String) authToken.get("name");
        }catch(Exception e){
            e.printStackTrace();
        }
        return name;
    }

    public static String getRole(HttpServletRequest req){
        JSONObject authToken = null;
        String role = null;
        try {
            authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
            role = (String) authToken.get("role");
        }catch(Exception e){
            e.printStackTrace();
        }
        return role;
    }

    public static String getAccountType(HttpServletRequest req){
        JSONObject authToken = null;
        String type = null;
        try {
            authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
            type = (String) authToken.get("type");
        }catch(Exception e){
            e.printStackTrace();
        }
        return type;
    }

    public static String getState(HttpServletRequest req){
        JSONObject authToken = null;
        String state = null;
        try {
            authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
            state = (String) authToken.get("state");
        }catch(Exception e){
            e.printStackTrace();
        }
        return state;
    }

    public static String getCity(HttpServletRequest req){
        JSONObject authToken = null;
        String city = null;
        try {
            authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
            city = (String) authToken.get("city");
        }catch(Exception e){
            e.printStackTrace();
        }
        return city;
    }



    public static JSONObject getAdminAuthToken(HttpServletRequest req, HttpServletResponse res) throws Exception{
        JSONObject tokenDetails = null;
        String authorization = null;
        StringTokenizer strTok = null;
        String token = null;

        try {
            authorization = req.getHeader("Authorization");
            if (authorization == null) {
                return null;
            }
            strTok = new StringTokenizer(authorization, " ");
            strTok.nextToken();
            token = strTok.nextToken();
            //System.out.println("token:"+token);
            if (JWTUtil.isTokenValid(token)) {
                tokenDetails = new JSONObject();
                tokenDetails.put("email",JWTUtil.getEmailFromToken(token));
                tokenDetails.put("name",JWTUtil.getNameFromToken(token));
                tokenDetails.put("role",JWTUtil.getRoleFromToken(token));
                //System.out.println("name:"+JWTUtil.getUsernameFromToken(token)+" role:"+JWTUtil.getRoleFromToken(token));
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return tokenDetails;
    }

    public static JSONObject getInput(HttpServletRequest req) throws Exception{
        JSONObject input = null;
        String inputs = null;
        try {
            inputs = (String) req.getAttribute(InputProcessor.REQUEST_DATA);
            if(inputs!=null) inputs = inputs.trim();
            //System.out.println("inputs:"+inputs);
            //inputs = applyRules(inputs);
            input = (JSONObject) new JSONParser().parse(inputs);
        }catch(Exception e){
            e.printStackTrace();
        }
        return input;
    }

    public static boolean validate(HttpServletRequest req, HttpServletResponse res) {

        JSONObject input = null;
        Set<ValidationMessage> errors = null;
        boolean valid = true;
        String func = null;

        try {
            input = InputProcessor.getInput(req);
            func = (String) input.get("_func");

            if(func == null){
                OutputProcessor.sendError(res,HttpServletResponse.SC_BAD_REQUEST,"_func missing");
                valid = false;
            }else{
                errors = JSONSchemaValidator.getHandle().validateSchema(func, input);
            }

            if(errors != null && errors.size()>0) {
                OutputProcessor.sendError(res,HttpServletResponse.SC_BAD_REQUEST, errors.toString());
                valid = false;
            }

        }catch(Exception e){
            e.printStackTrace();
            OutputProcessor.sendError(res,HttpServletResponse.SC_BAD_REQUEST,"Unknown input validation error");
            valid = false;
        }
        return valid;
    }

    public static String applyRules(String value) {
        if (value != null && value.trim().length() > 0) {
            try {
                value = URLDecoder.decode(value, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                //log.error(e.getMessage());
            }
            //value = StringEscapeUtils.unescapeHtml(value);
        } else {
            value = "";
        }
        return value;
    }
}
