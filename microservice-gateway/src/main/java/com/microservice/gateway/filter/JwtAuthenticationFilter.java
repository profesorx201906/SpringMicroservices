package com.microservice.gateway.filter;

import java.util.List;
import java.util.function.Predicate;

import com.microservice.gateway.exception.JwtTokenMalformedException;
import com.microservice.gateway.exception.JwtTokenMissingException;
import com.microservice.gateway.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter implements GatewayFilter {

  @Autowired
  private JwtUtil jwtUtil;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    ServerHttpRequest request = exchange.getRequest();

    final List<String> apiEndpoints = List.of("/auth/register", "/auth/login");

    // Permitir cualquier subruta bajo /api/student/**
    Predicate<ServerHttpRequest> isApiSecured = r ->
            apiEndpoints.stream().noneMatch(uri -> r.getURI().getPath().startsWith(uri)) &&
                    !r.getURI().getPath().startsWith("/api/student/");

    if (isApiSecured.test(request)) {
      if (!request.getHeaders().containsKey("Authorization")) {
        return unauthorizedResponse(exchange);
      }

      // Obtener el token y eliminar el prefijo "Bearer " si está presente
      String authHeader = request.getHeaders().getOrEmpty("Authorization").get(0);
      String token = authHeader.startsWith("Bearer ") ? authHeader.substring(7) : authHeader;

      try {
        jwtUtil.validateToken(token);
        Claims claims = jwtUtil.getClaims(token);

        // Extraer el ID del usuario desde `getSubject()`
        String userId = claims.getSubject();

        // Adjuntar el ID en los headers para que otros microservicios puedan usarlo
        exchange.getRequest().mutate().header("id", userId).build();

      } catch (JwtTokenMalformedException | JwtTokenMissingException e) {
        return badRequestResponse(exchange);
      }
    }

    return chain.filter(exchange);
  }

  private Mono<Void> unauthorizedResponse(ServerWebExchange exchange) {
    ServerHttpResponse response = exchange.getResponse();
    response.setStatusCode(HttpStatus.UNAUTHORIZED);
    return response.setComplete();
  }

  private Mono<Void> badRequestResponse(ServerWebExchange exchange) {
    ServerHttpResponse response = exchange.getResponse();
    response.setStatusCode(HttpStatus.BAD_REQUEST);
    return response.setComplete();
  }
}
