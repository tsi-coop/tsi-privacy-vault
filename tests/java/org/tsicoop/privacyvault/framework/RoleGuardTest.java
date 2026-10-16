package org.tsicoop.privacyvault.framework;

import org.junit.Test;

import java.util.Set;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RoleGuardTest {

    private static final Set<String> MUTATING = Set.of("create_entity", "update_entity");

    @Test
    public void systemAdminMayMutate() {
        assertTrue(RoleGuard.isAllowed("SYSTEM_ADMIN", "create_entity", MUTATING));
        assertTrue(RoleGuard.isAllowed("system_admin", "UPDATE_ENTITY", MUTATING));
    }

    @Test
    public void auditorMayNotMutate() {
        assertFalse(RoleGuard.isAllowed("AUDITOR", "create_entity", MUTATING));
        assertFalse(RoleGuard.isAllowed("AUDITOR", "Update_Entity", MUTATING));
    }

    @Test
    public void missingRoleFailsClosed() {
        assertFalse(RoleGuard.isAllowed(null, "create_entity", MUTATING));
        assertFalse(RoleGuard.isAllowed("", "create_entity", MUTATING));
    }

    @Test
    public void readOnlyFunctionsStayOpen() {
        assertTrue(RoleGuard.isAllowed("AUDITOR", "get_all_entities", MUTATING));
        assertTrue(RoleGuard.isAllowed(null, "get_all_entities", MUTATING));
    }
}
