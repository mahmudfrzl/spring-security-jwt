package kalemyazilimhome.az.springsecurityjwt.business.service;

public interface TokenService {
    public String generateToken(String userName);
    public boolean tokenValidate(String token);
    public String getUserFromToken(String token);
    public boolean isExpired(String token);
}
