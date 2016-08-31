package com.sncf.siv.poc.security.service;

import com.sncf.siv.poc.security.model.ResponseWrapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.web.bind.annotation.RequestMethod.GET;

@RestController
@RequestMapping("protected")
public class ProtectedController {

    @RequestMapping(method = GET)
    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    public ResponseWrapper getDaHoney() {

        // fake class just for testing purpose
        @AllArgsConstructor
        @Data
        class SensitiveInformation {
            String foo;
            String bar;
        }

        return new ResponseWrapper(new SensitiveInformation("ABCD", "XYZ"), null, null);
    }


}
