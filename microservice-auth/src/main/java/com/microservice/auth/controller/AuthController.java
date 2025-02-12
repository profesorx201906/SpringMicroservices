package com.microservice.auth.controller;


import com.microservice.auth.payload.request.LoginRequest;
import com.microservice.auth.payload.request.SignupRequest;
import com.microservice.auth.service.AuthSerivice;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;



import jakarta.validation.Valid;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/auth")
public class AuthController {

  @Autowired
  AuthSerivice authSerivice;

  @CrossOrigin(origins = "*")
  @PostMapping("/signIn")
  public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
    return authSerivice.authenticateUser(loginRequest);
  }

  @PostMapping("/signUp")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    return authSerivice.registerUser(signUpRequest);
  }
}
