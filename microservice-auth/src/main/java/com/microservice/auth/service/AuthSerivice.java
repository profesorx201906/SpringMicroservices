package com.microservice.auth.service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


import com.microservice.auth.entities.ERole;
import com.microservice.auth.entities.Role;
import com.microservice.auth.entities.User;
import com.microservice.auth.payload.request.LoginRequest;
import com.microservice.auth.payload.request.SignupRequest;
import com.microservice.auth.payload.response.JwtResponse;
import com.microservice.auth.payload.response.MessageResponse;
import com.microservice.auth.repository.RoleRepository;
import com.microservice.auth.repository.UserRepository;
import com.microservice.auth.security.jwt.JwtUtils;
import com.microservice.auth.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;



import jakarta.validation.Valid;

@Service
public class AuthSerivice {

  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserRepository userRepository;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
    List<String> roles = userDetails.getAuthorities().stream()
            .map(item -> item.getAuthority())
            .collect(Collectors.toList());

    return ResponseEntity.ok(new JwtResponse(jwt,
            userDetails.getId(),
            userDetails.getUsername(),
            userDetails.getEmail(),
            roles));
  }

  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity
              .badRequest()
              .body(new MessageResponse("Error: El usuario esta en uso!"));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity
              .badRequest()
              .body(new MessageResponse("Error:El correo esta en uso!"));
    }

    // Create new user's account
    User user = new User(signUpRequest.getUsername(),
            signUpRequest.getEmail(),
            encoder.encode(signUpRequest.getPassword()));

    Set<String> strRoles = signUpRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {
      Role userRole = roleRepository.findByName(ERole.ROLE_USER)
              .orElseThrow(() -> new RuntimeException("Error: Rol no encontrado"));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
          case "admin":
            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Error: Rol no encontrado"));
            roles.add(adminRole);

            break;
          case "mod":
            Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                    .orElseThrow(() -> new RuntimeException("Error: Rol no encontrado"));
            roles.add(modRole);
            break;
          case "select":
            Role selectRole = roleRepository.findByName(ERole.ROLE_SELECT)
                    .orElseThrow(() -> new RuntimeException("Error: Rol no encontrado"));
            roles.add(selectRole);
            break;
          case "update":
            Role updateRole = roleRepository.findByName(ERole.ROLE_UPDATE)
                    .orElseThrow(() -> new RuntimeException("Error: Rol no encontrado"));
            roles.add(updateRole);
            break;
          case "delete":
            Role deleteRole = roleRepository.findByName(ERole.ROLE_DELETE)
                    .orElseThrow(() -> new RuntimeException("Error: Rol no encontrado"));
            roles.add(deleteRole);
            break;
          case "create":
            Role createRole = roleRepository.findByName(ERole.ROLE_CREATE)
                    .orElseThrow(() -> new RuntimeException("Error: Rol no encontrado"));
            roles.add(createRole);

            break;
          default:
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Rol no encontrado"));
            roles.add(userRole);
        }
      });
    }

    user.setRoles(roles);
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }

}
