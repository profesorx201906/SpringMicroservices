package com.microservice.auth.entities.utility;

import java.util.HashSet;
import java.util.Set;

import com.microservice.auth.entities.ERole;
import com.microservice.auth.entities.Role;
import com.microservice.auth.entities.User;
import com.microservice.auth.repository.RoleRepository;
import com.microservice.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class CreateRole implements CommandLineRunner {

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  UserRepository userRepository;

  @Override
  public void run(String... args) throws Exception {
    if (roleRepository.findAll().size() == 0) {
      Role rolAdmin = new Role(ERole.ROLE_ADMIN);
      Role rolUser = new Role(ERole.ROLE_USER);
      Role rolModerator = new Role(ERole.ROLE_MODERATOR);
      Role rolSelect = new Role(ERole.ROLE_SELECT);
      Role rolUpdate = new Role(ERole.ROLE_UPDATE);
      Role rolCreate = new Role(ERole.ROLE_CREATE);
      Role rolDelete = new Role(ERole.ROLE_DELETE);

      roleRepository.save(rolAdmin);
      roleRepository.save(rolUser);
      roleRepository.save(rolModerator);
      roleRepository.save(rolSelect);
      roleRepository.save(rolUpdate);
      roleRepository.save(rolCreate);
      roleRepository.save(rolDelete);
    }

    if (userRepository.findAll().size() == 0) {
      Role userRole = roleRepository.findByName(ERole.ROLE_ADMIN).get();
      Set<Role> roles = new HashSet<>();
      roles.add(userRole);
      User usuario = new User();
      usuario.setUsername("admin");
      usuario.setEmail("admin@unir.net");
      usuario.setPassword("$2a$10$YPfYD7zPaMCOuiyI3Jyi9egWnF5DJLNqxmXzd2vQG1oa2ZA7q5q1O");
      usuario.setRoles(roles);
      userRepository.save(usuario);
    }

  }
}
