package org.tsicoop.privacyvault.framework;

import jakarta.servlet.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Server-side gate for the static admin console pages.
 *
 * These pages used to be served to any HTTP client. The only login check was
 * client-side JavaScript reading localStorage after the page had already been
 * delivered. This filter runs before the default servlet serves the file and
 * requires a valid admin JWT, carried in an HttpOnly session cookie so plain
 * browser navigation can present it. Otherwise the request is redirected to
 * the login page.
 *
 * API authentication is unchanged: /api/admin/* and /api/client/* calls are
 * validated independently by InterceptingFilter on every request.
 */
public class ConsoleAuthFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String token = readSessionCookie(req);
        if (token == null || !JWTUtil.isTokenValid(token)) {
            res.sendRedirect("/index.html");
            return;
        }

        chain.doFilter(request, response);
    }

    private String readSessionCookie(HttpServletRequest req) {
        Cookie[] cookies = req.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (InputProcessor.CONSOLE_SESSION_COOKIE.equals(c.getName())) {
                return c.getValue();
            }
        }
        return null;
    }
}
