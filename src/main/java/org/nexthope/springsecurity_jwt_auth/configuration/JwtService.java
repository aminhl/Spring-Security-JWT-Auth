package org.nexthope.springsecurity_jwt_auth.configuration;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

/**
 * Service class for handling JWT (JSON Web Token) operations.
*/
@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${jwt.secret}")
    private String jwtSecret;

    /**
     * Extracts the username from the provided JWT access token.
     * @param accessToken the JWT access token from which the username is to be extracted; must not be null or empty
     * @return the username extracted from the token
     */
    public String extractUsername(final String accessToken) {
        return extractClaim(accessToken, Claims::getSubject);
    }

    /**
     * Extract a specific claim from the provided JWT access token.
     * @param accessToken the JWT access token from which the specific claim is to be extracted; must not be null or empty
     * @param claimsResolver a function that takes the JWT claims and returns the desired claim value
     * @return the extracted claim value of type {@code T}
     * @param <T> the type of the claim to be extracted
     */
    private <T> T extractClaim(String accessToken, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaims(accessToken);
        return claimsResolver.apply(claims);
    }

    /**
     * Extracts all claims from the provided JWT access token.
     * @param accessToken the JWT access token from which the claims are to be extracted; must not be null or empty.
     * @return the claims contained in the token
     * @throws RuntimeException if the Jwt access token is null, empty or invalid
     */
    private Claims extractAllClaims(final String accessToken) {
        try {
            return Jwts
                    .parserBuilder()
                    .setSigningKey(getSingingKey())
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();
        }
        catch (JwtException e) {
            throw new RuntimeException("Invalid JWT token: " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("JWT token is null or empty", e);
        }
    }

    /**
     * Validates the provided JWT access token by checking its integrity and expiration status.
     * <p>
     * The token is considered valid if the extracted username matches the provided user details
     * and the token is not expired.
     * </p>
     * @param accessToken the JWT access token to be validated; must not be null or empty
     * @param user the user details against which the token's username is validated; must not be null
     * @return {@code true} if the token is valid and belongs to the provided user, {@code false} otherwise
     */
    public boolean isTokenValid(final String accessToken, UserDetails user) {
        try {
            String userName = extractUsername(accessToken);
            return userName.equals(user.getUsername()) && !isTokenExpired(accessToken);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Validates the expiration status of the provided JWT access token.
     * @param accessToken the JWT access token to be validated; must not be null or empty
     * @return {@code true} if the token is expired, {@code false} otherwise
     */
    private boolean isTokenExpired(final String accessToken) {
        try {
            return extractTokenExpiration(accessToken).before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * Extract the expiration date from the provided JWT access token.
     * @param accessToken the JWT access token from which the expiration date to be extracted; must not be null or empty
     * @return the expiration date of the token
     */
    private Date extractTokenExpiration(final String accessToken) {
        return extractClaim(accessToken, Claims::getExpiration);
    }

    /**
     * Generates and returns the signing key used for verifying and signing JWT tokens.
     * <p>
     * The method decodes the secret key from a Base64-encoded string and uses it
     * to generate an HMAC-SHA key suitable for JWT signing.
     * </p>
     * @return the signing {@link Key} derived from the configured secret key
     * @throws RuntimeException if the JWT secret key is invalid
     */
    private Key getSingingKey() {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid JWT secret key", e);
        }
    }

}
