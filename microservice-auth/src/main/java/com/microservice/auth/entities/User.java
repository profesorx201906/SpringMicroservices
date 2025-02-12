package com.microservice.auth.entities;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(columnNames = "username"),
        @UniqueConstraint(columnNames = "email")
})
public class User implements UserDetails {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @NotBlank
  @Size(max = 20)
  private String username;

  @NotBlank
  @Size(max = 50)
  @Email
  private String email;

  @NotBlank
  @Size(max = 120)
  private String password;

  @ManyToMany(fetch = FetchType.LAZY)
  @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
  private Set<Role> roles = new HashSet<>();

  public User(String username, String email, String password) {
    this.username = username;
    this.email = email;
    this.password = password;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    Set<GrantedAuthority> authorities = new HashSet<>();

    // Agregamos los roles como "ROLE_NOMBRE"
    roles.forEach(role -> {
      authorities.add(new SimpleGrantedAuthority(role.getName().name()));
    });

    // También podemos agregar permisos adicionales si existen en la entidad
    return authorities;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }
}
