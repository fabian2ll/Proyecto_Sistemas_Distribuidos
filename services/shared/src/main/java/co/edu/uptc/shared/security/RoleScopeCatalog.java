package co.edu.uptc.shared.security;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public final class RoleScopeCatalog {

    public static final String ROLE_ADMIN = "ADMIN";
    public static final String ROLE_OFFICER = "OFFICER";
    public static final String ROLE_AUDITOR = "AUDITOR";

    public static final String CREATE_CONTRACT = "create:contract";
    public static final String UPDATE_CONTRACT = "update:contracts";
    public static final String VIEW_CONTRACTS = "view:contracts";
    public static final String VIEW_CONTRACTS_BY_ID = "view:contracts:by_id";
    public static final String CREATE_SUPPLIER = "create:supplier";
    public static final String UPDATE_SUPPLIER = "update:supplier";
    public static final String VIEW_SUPPLIERS = "view:suppliers";
    public static final String VIEW_AUDIT = "view:audit";

    private static final Map<String, Set<String>> ROLE_SCOPES = Map.of(
            ROLE_ADMIN, Set.of(
                    CREATE_CONTRACT,
                    UPDATE_CONTRACT,
                    VIEW_CONTRACTS,
                    VIEW_CONTRACTS_BY_ID,
                    CREATE_SUPPLIER,
                    UPDATE_SUPPLIER,
                    VIEW_SUPPLIERS,
                    VIEW_AUDIT
            ),
            ROLE_OFFICER, Set.of(
                    CREATE_CONTRACT,
                    UPDATE_CONTRACT,
                    VIEW_CONTRACTS,
                    VIEW_CONTRACTS_BY_ID,
                    CREATE_SUPPLIER,
                    UPDATE_SUPPLIER,
                    VIEW_SUPPLIERS
            ),
            ROLE_AUDITOR, Set.of(
                    VIEW_CONTRACTS,
                    VIEW_CONTRACTS_BY_ID,
                    VIEW_AUDIT
            )
    );

    private RoleScopeCatalog() {
    }

    public static Set<String> scopesForRole(String roleName) {
        if (roleName == null) {
            return Set.of();
        }

        return ROLE_SCOPES.getOrDefault(roleName.trim().toUpperCase(), Set.of());
    }

    public static Set<String> allScopes() {
        Set<String> scopes = new LinkedHashSet<>();
        ROLE_SCOPES.values().forEach(scopes::addAll);
        return Set.copyOf(scopes);
    }
}