package com.microservice.auth.security.jwt;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import com.microservice.auth.entities.utility.Environment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;



import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import io.jsonwebtoken.security.SignatureException;

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  private String jwtSecret = Environment.SECRET_KEY;

  private int jwtExpirationMs = Environment.JWT_EXPIRATION_TIME;

  public String generateJwtToken(Authentication authentication) {

    UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();
    List<String> roles = userPrincipal.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority).collect(Collectors.toList());

    Date currentDate = new Date();
    Date expireDate = new Date(currentDate.getTime() + jwtExpirationMs);

    return Jwts.builder()
            .subject(userPrincipal.getUsername())
            .claim("roles", roles)
            .issuedAt(currentDate)
            .expiration(expireDate)
            .signWith(getKey())
            .compact();
  }

  public String getUserNameFromJwtToken(String token) {
    return getClaims(token, Claims::getSubject);
  }

  public boolean validateJwtToken(String authToken) {
    try {
      Jwts.parser().verifyWith((SecretKey) getKey()).build().parseSignedClaims(authToken).getPayload();
      return true;
    } catch (SignatureException e) {
      logger.error("Firma Invalida para JWT : {}", e.getMessage());
    } catch (MalformedJwtException e) {
      logger.error("Token JWT Invalido : {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("El token JWT ha expirado : {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("El token JWT no es soportado : {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("La cadena JWT esta vacia : {}", e.getMessage());
    }

    return false;
  }

  public <T> T getClaims(String token, Function<Claims, T> claimsResolver) {
    return claimsResolver.apply(Jwts.parser()
            .verifyWith((SecretKey) getKey())
            .build()
            .parseSignedClaims(token)
            .getPayload());
  }

  public Key getKey() {
    byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
