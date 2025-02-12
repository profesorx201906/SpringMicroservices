package com.microservice.gateway.util;

import com.microservice.gateway.exception.JwtTokenMalformedException;
import com.microservice.gateway.exception.JwtTokenMissingException;
import com.microservice.gateway.utility.Environment;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtil {


  private String jwtSecret = Environment.SECRET_KEY;

 
  public void validateToken(final String token) throws JwtTokenMalformedException, JwtTokenMissingException {
    try {
      Jwts.parser().verifyWith((SecretKey) getKey()).build().parseSignedClaims(token).getPayload();
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

  public <T> T getClaims(String token, Function<Claims, T> claimsResolver) {
    return claimsResolver.apply(Jwts.parser()
            .verifyWith((SecretKey) getKey())
            .build()
            .parseSignedClaims(token)
            .getPayload());
  }
  public Claims getAllClaims(String token) { // Nuevo método para obtener todos los Claims
    try {
      return Jwts.parser()
              .verifyWith((SecretKey) getKey())
              .build()
              .parseSignedClaims(token)
              .getPayload();
    } catch (ExpiredJwtException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException | SignatureException ex) {
      throw new RuntimeException("Invalid JWT token.");
    }
  }
  public Key getKey() {
    byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
