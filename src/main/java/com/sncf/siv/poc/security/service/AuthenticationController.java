package com.sncf.siv.poc.security.service;

import com.nimbusds.jose.JOSEException;
import com.sncf.siv.poc.security.JwtUtils;
import com.sncf.siv.poc.security.model.AuthenticationRequest;
import com.sncf.siv.poc.security.model.AuthenticationResponse;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.charset.Charset;

import static com.sncf.siv.poc.security.JwtUtils.generateHMACToken;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

@RestController
@RequestMapping("auth")
public class AuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @RequestMapping(method = POST)
    public ResponseEntity<?> authenticationRequest(@RequestBody AuthenticationRequest authenticationRequest)
            throws AuthenticationException, IOException, JOSEException {

        String username = authenticationRequest.getUsername();
        String password = authenticationRequest.getPassword();

        // throws authenticationException if it fails !
        Authentication authentication = this.authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String secret = IOUtils.toString(getClass().getClassLoader().getResourceAsStream("secret.key"), Charset.defaultCharset());
        int expirationInMinutes = 24*60;

        String token = generateHMACToken(username, authentication.getAuthorities(), secret, expirationInMinutes);

        // Return the token
        return ResponseEntity.ok(new AuthenticationResponse(token));
    }


}
