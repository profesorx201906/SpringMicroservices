package com.microservice.gateway.config;

import com.microservice.gateway.filter.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfig {

  @Autowired
  private JwtAuthenticationFilter filter;

  @Bean
  public RouteLocator routes(RouteLocatorBuilder builder) {
    return builder.routes()
            // Rutas públicas (sin filtro)
            .route("msvc-auth", r -> r.path("/auth/**").uri("lb://msvc-auth"))

            // Rutas protegidas (con filtro)
            .route("alert", r -> r.path("/alert/**").filters(f -> f.filter(filter)).uri("lb://alert"))
            .route("echo", r -> r.path("/echo/**").filters(f -> f.filter(filter)).uri("lb://echo"))
            .route("msvc-course", r -> r.path("/api/course/**").filters(f -> f.filter(filter)).uri("lb://msvc-course"))

            // Permitir el acceso a /api/student/** sin filtro (ya lo gestiona el filtro en JwtAuthenticationFilter)
            .route("msvc-student", r -> r.path("/api/student/**").uri("lb://msvc-student"))

            .route("hello", r -> r.path("/hello/**").filters(f -> f.filter(filter)).uri("lb://hello"))
            .build();
  }
}

