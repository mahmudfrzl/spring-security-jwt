package kalemyazilimhome.az.springsecurityjwt.api;

import kalemyazilimhome.az.springsecurityjwt.api.request.LoginRequest;
import kalemyazilimhome.az.springsecurityjwt.business.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/login")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    @PostMapping
    public ResponseEntity<String> login(LoginRequest loginRequest){
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUserName(),loginRequest.getPassword()));
            return ResponseEntity.ok(tokenService.generateToken(loginRequest.getUserName()));
        }
        catch (Exception e){
            throw e;
        }
    }
}
