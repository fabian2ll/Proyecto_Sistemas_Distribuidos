package co.edu.uptc.shared.security.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declara el scope mínimo que debe tener el usuario autenticado
 * para acceder al endpoint anotado.
 *
 * <p>El valor debe coincidir con alguno de los scopes presentes en
 * el header {@code X-Scopes} inyectado por el API-Gateway.</p>
 *
 * <pre>{@code
 * @GetMapping
 * @RequiresScope("contracts:read")
 * public ResponseEntity<?> list() { ... }
 *
 * @PostMapping
 * @RequiresScope("contracts:write")
 * public ResponseEntity<?> create(@RequestBody ...) { ... }
 * }</pre>
 *
 * <p>Si el usuario no posee el scope requerido la respuesta será
 * {@code 403 Forbidden}. Si el endpoint no está anotado se permite
 * el acceso (ya validado por {@link GatewayAuthFilter}).</p>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresScope {

    /** Scope requerido, e.g. {@code "contracts:read"}, {@code "contracts:write"}. */
    String value();
}