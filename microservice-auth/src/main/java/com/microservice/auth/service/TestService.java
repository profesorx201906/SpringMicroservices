package com.microservice.auth.service;


import org.springframework.stereotype.Service;

@Service
public class TestService {

  public String allAccess() {
    return "Public Content.";
  }

  public String userAccess() {
    return "Contenido usuario";
  }

  public String moderatorAccess() {
    return "Contenido Moderador";
  }

  public String adminAccess() {
    return "Contenido Administrador";
  }

  public String deleteAccess() {
    return "Contenido para eliminar";
  }


}
