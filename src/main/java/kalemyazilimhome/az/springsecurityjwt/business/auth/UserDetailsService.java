package kalemyazilimhome.az.springsecurityjwt.business.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {
    Map<String,String> users = new HashMap<>();
    private final BCryptPasswordEncoder passwordEncoder;

    @PostConstruct
    public void init(){

        users.put("temelt",passwordEncoder.encode("123"));
    }
    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        if(users.containsKey(userName)){
            return new User(userName,users.get(userName),new ArrayList<>());
        }
        throw new UsernameNotFoundException(userName);
    }

}
