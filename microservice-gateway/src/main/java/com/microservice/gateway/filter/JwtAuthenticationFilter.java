package com.microservice.gateway.filter;

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

import java.util.List;
import java.util.function.Predicate;

@Component
public class JwtAuthenticationFilter implements GatewayFilter {

  @Autowired
  private JwtUtil jwtUtil;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    ServerHttpRequest request = exchange.getRequest();

    final List<String> openApiEndpoints = List.of("/api/auth/signIn", "/api/auth/signUp");
    final List<String> studentApiPrefix = List.of("/api/student/");

    Predicate<ServerHttpRequest> isApiSecured = r ->
            openApiEndpoints.stream().noneMatch(uri -> r.getURI().getPath().equals(uri)) &&
                    studentApiPrefix.stream().noneMatch(prefix -> r.getURI().getPath().startsWith(prefix));

    if (isApiSecured.test(request)) {
      if (!request.getHeaders().containsKey("Authorization")) {
        return unauthorizedResponse(exchange);
      }

      String authHeader = request.getHeaders().getOrEmpty("Authorization").get(0);
      String token = authHeader.startsWith("Bearer ") ? authHeader.substring(7) : authHeader;

      try {
        jwtUtil.validateToken(token);
        Claims claims = jwtUtil.getAllClaims(token); // Usamos el nuevo método getAllClaims

        if (claims != null) {
          String userId = claims.getSubject();
          exchange.getRequest().mutate().header("id", userId).build();
        } else {
          return badRequestResponse(exchange);
        }

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