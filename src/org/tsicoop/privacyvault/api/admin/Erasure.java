package org.tsicoop.privacyvault.api.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.tsicoop.privacyvault.framework.Action;
import org.tsicoop.privacyvault.framework.ErasureService;
import org.tsicoop.privacyvault.framework.InputProcessor;
import org.tsicoop.privacyvault.framework.OutputProcessor;

/**
 * Admin API for erasure by principal: shred, legal holds, the
 * Erasure Register and the erasure certificate (docs/design/architecture.md).
 * Everything that destroys data or changes policy state needs SYSTEM_ADMIN.
 * Reading the register and certificates is open to any signed-in admin.
 */
public class Erasure implements Action {

    private static final String ROLE_SYSTEM_ADMIN = "SYSTEM_ADMIN";

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        String who = InputProcessor.getEmail(req);
        String role = InputProcessor.getRole(req);
        String ip = req.getRemoteAddr();
        String ua = req.getHeader("User-Agent");
        try {
            JSONObject input = InputProcessor.getInput(req);
            if (input == null) throw new Exception("Invalid JSON payload.");
            String func = (String) input.get("_func");
            if (func == null) {
                OutputProcessor.sendError(res, 400, "Missing _func parameter.");
                return;
            }
            func = func.toLowerCase();

            if (isMutating(func) && !ROLE_SYSTEM_ADMIN.equalsIgnoreCase(role)) {
                ErasureService.audit("ERASURE_" + func.toUpperCase(), who, ip, ua, "DENIED", "role");
                OutputProcessor.sendError(res, HttpServletResponse.SC_FORBIDDEN, "SYSTEM_ADMIN role required.");
                return;
            }

            switch (func) {
                case "shred_principal": {
                    String principal = (String) input.get("principal_id");
                    if (!principal.equals(input.get("confirm"))) {
                        OutputProcessor.sendError(res, 400, "confirm must equal principal_id. Shredding is irreversible.");
                        return;
                    }
                    send(res, ErasureService.shredPrincipal(principal, who, ip, ua));
                    break;
                }
                case "shred_record": {
                    String ref = (String) input.get("reference_key");
                    if (!ref.equals(input.get("confirm"))) {
                        OutputProcessor.sendError(res, 400, "confirm must equal reference_key. Shredding is irreversible.");
                        return;
                    }
                    send(res, ErasureService.shredRecord(ref, who, ip, ua));
                    break;
                }
                case "place_legal_hold":
                    send(res, ErasureService.placeHold((String) input.get("principal_id"), (String) input.get("reason"),
                            (String) input.get("case_ref"), who, ip, ua));
                    break;
                case "release_legal_hold":
                    send(res, ErasureService.releaseHold(((Number) input.get("hold_id")).intValue(), who, ip, ua));
                    break;
                case "list_legal_holds": {
                    JSONObject out = new JSONObject();
                    out.put("success", true);
                    out.put("holds", ErasureService.listHolds(Boolean.TRUE.equals(input.get("open_only"))));
                    OutputProcessor.send(res, 200, out);
                    break;
                }
                case "get_erasure_register": {
                    JSONObject out = new JSONObject();
                    out.put("success", true);
                    out.put("register", ErasureService.register((String) input.get("state")));
                    OutputProcessor.send(res, 200, out);
                    break;
                }
                case "get_erasure_certificate":
                    send(res, ErasureService.certificate((String) input.get("principal_id")));
                    break;
                case "get_erasure_job": {
                    int limit = input.get("limit") instanceof Number ? ((Number) input.get("limit")).intValue() : 50;
                    OutputProcessor.send(res, 200, ErasureService.jobStatus(limit));
                    break;
                }
                case "run_erasure_job": {
                    JSONObject out = ErasureService.runDue(ErasureService.TRIGGER_MANUAL);
                    OutputProcessor.send(res, 200, out);
                    break;
                }
                default:
                    OutputProcessor.sendError(res, 400, "Unknown function: " + func);
            }
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.sendError(res, 500, "Erasure error: " + e.getMessage());
        }
    }

    private static boolean isMutating(String func) {
        switch (func) {
            case "shred_principal":
            case "shred_record":
            case "place_legal_hold":
            case "release_legal_hold":
            case "run_erasure_job":
                return true;
            default:
                return false;
        }
    }

    private static void send(HttpServletResponse res, ErasureService.Outcome o) {
        OutputProcessor.send(res, o.status, o.body);
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST for erasure operations.", req.getRequestURI());
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
