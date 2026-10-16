package org.tsicoop.privacyvault.api.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.sql.Connection;
import org.json.simple.JSONObject;
import org.tsicoop.privacyvault.framework.Action;
import org.tsicoop.privacyvault.framework.EntityRules;
import org.tsicoop.privacyvault.framework.ErasureService;
import org.tsicoop.privacyvault.framework.InputProcessor;
import org.tsicoop.privacyvault.framework.KmsProviderFactory;
import org.tsicoop.privacyvault.framework.OutputProcessor;
import org.tsicoop.privacyvault.framework.PoolDB;

/**
 * Read-only view of the vault's deployment settings for the console Settings page.
 * Everything here is set through the environment (.env) and needs a restart to change.
 * Returns env var names and non-secret values only: never keys, tokens, secrets or passwords.
 * Key anchor actions stay on /api/admin/keyanchor.
 */
public class Settings implements Action {

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            JSONObject input = InputProcessor.getInput(req);
            String func = input == null ? null : (String) input.get("_func");
            if (!"get_settings".equalsIgnoreCase(func)) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown function", req.getRequestURI());
                return;
            }
            OutputProcessor.send(res, 200, getSettings());
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    private JSONObject getSettings() {
        JSONObject out = new JSONObject();

        JSONObject general = new JSONObject();
        general.put("environment", env("TSI_PRIVACY_VAULT_ENV"));
        general.put("environment_var", "TSI_PRIVACY_VAULT_ENV");
        general.put("node_id", env("TSI_PRIVACY_VAULT_NODE_ID"));
        general.put("node_id_var", "TSI_PRIVACY_VAULT_NODE_ID");
        general.put("max_upload_kb", EntityRules.systemMaxUploadKb());
        general.put("max_upload_var", "TSI_PRIVACY_VAULT_MAX_UPLOAD_KB");
        out.put("general", general);

        JSONObject kms = new JSONObject();
        kms.put("configured_anchor", KmsProviderFactory.getConfiguredAnchor());
        kms.put("env", KmsProviderFactory.ENV_PROVIDER);
        kms.put("healthy", KmsProviderFactory.isHealthy());
        kms.put("health_error", KmsProviderFactory.getHealthError());
        kms.put("aws_region", env("TSI_PRIVACY_VAULT_AWS_REGION"));
        kms.put("aws_endpoint", env("TSI_PRIVACY_VAULT_AWS_ENDPOINT"));
        // Key id is an identifier, not a secret, but show only whether one is set.
        kms.put("aws_key_configured", env("TSI_PRIVACY_VAULT_AWS_KMS_KEY_ID") != null);
        out.put("kms", kms);

        PoolDB pool = null;
        Connection conn = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            out.put("file_storage", Dashboard.getFileStorage(conn, pool));
        } catch (Exception e) {
            JSONObject fs = new JSONObject();
            fs.put("error", "File storage details unavailable.");
            out.put("file_storage", fs);
        } finally {
            if (pool != null && conn != null) pool.cleanup(null, null, conn);
        }

        JSONObject job = new JSONObject();
        long minutes = ErasureService.getIntervalMinutes();
        job.put("interval_minutes", minutes);
        job.put("enabled", minutes > 0);
        job.put("env", ErasureService.ENV_JOB_MINUTES);
        out.put("erasure_job", job);

        out.put("_success", true);
        return out;
    }

    private static String env(String name) {
        String v = System.getenv(name);
        return (v == null || v.trim().isEmpty()) ? null : v.trim();
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "GET method not supported.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT method not supported.", req.getRequestURI());
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method not supported.", req.getRequestURI());
    }
}
