package com.microservice.auth.util;

import com.microservice.auth.exception.JwtTokenMalformedException;
import com.microservice.auth.exception.JwtTokenMissingException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
@Component
public class JwtUtil {

  private final SecretKey secretKey;

  @Value("${jwt.token.validity}")
  private long tokenValidity;

  public JwtUtil(@Value("${jwt.secret}") String jwtSecret) {
    byte[] decodedKey = Base64.getDecoder().decode(jwtSecret);
    this.secretKey = Keys.hmacShaKeyFor(decodedKey);
  }

  public String generateToken(String id) {
    Claims claims = Jwts.claims().setSubject(id);
    long nowMillis = System.currentTimeMillis();
    long expMillis = nowMillis + tokenValidity;
    Date exp = new Date(expMillis);

    return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(new Date(nowMillis))
            .setExpiration(exp)
            .signWith(secretKey, SignatureAlgorithm.HS512)
            .compact();
  }

  public Claims getClaims(final String token) {
    return Jwts.parserBuilder()
            .setSigningKey(secretKey)
            .build()
            .parseClaimsJws(token)
            .getBody();
  }
}
