package com.microservice.gateway.util;

import com.microservice.gateway.exception.JwtTokenMalformedException;
import com.microservice.gateway.exception.JwtTokenMissingException;
import io.jsonwebtoken.*;
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

  public void validateToken(final String token) throws JwtTokenMalformedException, JwtTokenMissingException {
    try {
      Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
    } catch (SignatureException ex) {
      throw new JwtTokenMalformedException("Invalid JWT signature");
    } catch (MalformedJwtException ex) {
      throw new JwtTokenMalformedException("Invalid JWT token");
    } catch (ExpiredJwtException ex) {
      throw new JwtTokenMalformedException("Expired JWT token");
    } catch (UnsupportedJwtException ex) {
      throw new JwtTokenMalformedException("Unsupported JWT token");
    } catch (IllegalArgumentException ex) {
      throw new JwtTokenMissingException("JWT claims string is empty.");
    }
  }
}
