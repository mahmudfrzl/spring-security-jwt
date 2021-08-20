package kalemyazilimhome.az.springsecurityjwt.business.auth;

import kalemyazilimhome.az.springsecurityjwt.business.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

@Component
@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {
    private final TokenService tokenService;
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        /*
        * Bearer 123hab2355
        * */
        String userName =null;
        String token =null;
        final String authHeader = request.getHeader("Authorization");
        if(authHeader !=null && authHeader.contains("Bearer")){
            token = authHeader.substring(7);
            try {
                userName = tokenService.getUserFromToken(token);
            }catch (Exception e){
                System.out.println(e.getMessage());
            }
        }
        if(userName !=null && token !=null && SecurityContextHolder.getContext().getAuthentication() == null){
            if(tokenService.tokenValidate(token)){
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(userName,null,new ArrayList<>());
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        filterChain.doFilter(request,response);
    }
}
