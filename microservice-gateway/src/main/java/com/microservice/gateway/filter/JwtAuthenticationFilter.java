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

    final List<String> apiEndpoints = List.of("/register", "/login");

    // Permitir cualquier subruta bajo /api/student/**
    Predicate<ServerHttpRequest> isApiSecured = r ->
            apiEndpoints.stream().noneMatch(uri -> r.getURI().getPath().startsWith(uri)) &&
                    !r.getURI().getPath().startsWith("/api/student/");

    if (isApiSecured.test(request)) {
      if (!request.getHeaders().containsKey("Authorization")) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
      }

      final String token = request.getHeaders().getOrEmpty("Authorization").get(0);

      try {
        jwtUtil.validateToken(token);
      } catch (JwtTokenMalformedException | JwtTokenMissingException e) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.BAD_REQUEST);
        return response.setComplete();
      }

      Claims claims = jwtUtil.getClaims(token);
      exchange.getRequest().mutate().header("id", String.valueOf(claims.get("id"))).build();
    }

    return chain.filter(exchange);
  }
}
