package kalemyazilimhome.az.springsecurityjwt.business.auth;

import io.jsonwebtoken.Claims;
import kalemyazilimhome.az.springsecurityjwt.business.service.TokenService;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;

@Service
public class TokenManager implements TokenService {

    private static final int validity = 5*60*1000;
    Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    @Override
    public String generateToken(String userName) {

        return  Jwts.builder().
                setSubject(userName).
                setExpiration(new Date(System.currentTimeMillis()+validity)).//ne zamana qeder aktiv
                setIssuer("kalemyazilim.az").//kim yaratdi
                setIssuedAt(new Date(System.currentTimeMillis())).//ne zaman yarandi
                signWith(key).
                compact();

    }

    @Override
    public boolean tokenValidate(String token) {
        if(generateToken(token) != null && isExpired(token)){
            return true;
        }
        return false;
    }

    @Override
    public String getUserFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.getSubject();
    }



    @Override
    public boolean isExpired(String token) {
        Claims claims =getClaims(token);
        return claims.getExpiration().after(new Date(System.currentTimeMillis()));
    }
    private Claims getClaims(String token) {
        return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
    }
}
