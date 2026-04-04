package uptc.edu.co.ms_contracts.controllers;


import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import co.edu.uptc.shared.security.RoleScopeCatalog;
import co.edu.uptc.shared.security.annotations.RequiresScope;

@RestController
public class GetController {

    @GetMapping("/contracts")
    @RequiresScope(RoleScopeCatalog.VIEW_CONTRACTS)
    public String getContracts(
        @RequestHeader HttpHeaders headers
    ) {
        headers.forEach((key, value) -> {
            System.out.println(key + " " + value);
        });
        return "Contracts";
    }
}
