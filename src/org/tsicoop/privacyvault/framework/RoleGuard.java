package org.tsicoop.privacyvault.framework;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Set;

/**
 * Role enforcement for the admin console APIs. Authentication (a valid JWT) is checked by
 * InterceptingFilter; this decides what the signed-in role may do.
 *
 * Mutating functions need SYSTEM_ADMIN. Read-only functions stay open to any signed-in admin
 * (AUDITOR). A missing or unknown role is denied, so the check fails closed.
 */
public final class RoleGuard {

    public static final String SYSTEM_ADMIN = "SYSTEM_ADMIN";

    private RoleGuard() { }

    /** Pure decision, kept separate from the servlet types so it can be unit tested. */
    public static boolean isAllowed(String role, String func, Set<String> mutatingFuncs) {
        if (func == null || !mutatingFuncs.contains(func.toLowerCase())) return true;
        return SYSTEM_ADMIN.equalsIgnoreCase(role);
    }

    /**
     * Returns true when the call may proceed. Otherwise writes a 403, records a DENIED event in
     * event_log and returns false; the caller must return immediately.
     */
    public static boolean allow(HttpServletRequest req, HttpServletResponse res, String area,
                                String func, Set<String> mutatingFuncs) {
        String role = InputProcessor.getRole(req);
        if (isAllowed(role, func, mutatingFuncs)) return true;
        deny(req, res, area, func);
        return false;
    }

    /** Requires SYSTEM_ADMIN for every function of the endpoint. */
    public static boolean allowSystemAdminOnly(HttpServletRequest req, HttpServletResponse res,
                                               String area, String func) {
        if (SYSTEM_ADMIN.equalsIgnoreCase(InputProcessor.getRole(req))) return true;
        deny(req, res, area, func);
        return false;
    }

    private static void deny(HttpServletRequest req, HttpServletResponse res, String area, String func) {
        String who = InputProcessor.getEmail(req);
        ErasureService.audit("ADMIN_" + area.toUpperCase() + ":" + String.valueOf(func).toUpperCase(),
                who == null ? "unknown" : who, req.getRemoteAddr(), req.getHeader("User-Agent"),
                "DENIED", "role");
        OutputProcessor.sendError(res, HttpServletResponse.SC_FORBIDDEN, "SYSTEM_ADMIN role required.");
    }
}
