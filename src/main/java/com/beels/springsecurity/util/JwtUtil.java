package com.beels.springsecurity.util;

import com.beels.springsecurity.services.MyUserDetailService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtil {
    private String SECRET_KEY = "my_secret_key";

    public String extractUserName (String token){
        return extractClaim(token,Claims::getSubject);
    }
    public Date extractExpirationDate(String token){
        return extractClaim(token,Claims::getExpiration);
    }
    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);

    }
    private Claims extractAllClaims(String token){
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    private boolean isTokenExpired(String token){

        return  false;
    }

    public String createToken(UserDetails userDetails){
        Map<String,Object> claims = new HashMap<>();
        String subject = userDetails.getUsername();

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10 ))
                .signWith(SignatureAlgorithm.HS256,SECRET_KEY).compact();
    }

    public boolean validateToken(String token, UserDetails userDetails){
        return true;
    }
}
