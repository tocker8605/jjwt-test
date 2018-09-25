package my.tocker.jwt.config;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class MyUserDetailsService implements UserDetailsService {

    private static List<String> usernameList = Arrays.asList("tocker", "admin");

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 원래 여기서 데이터베이스로부터 유저검증을 하도록 하는게 맞지만. 일단 연습이기 때문에 인메모리 처리
        if(!usernameList.contains(username)){
            throw new UsernameNotFoundException(username);
        }

        return User.withUsername(username)
                .password("$2a$10$5DF/j5hHnbeHyh85/0Bdzu1HV1KyJKZRt2GhpsfzQ8387A/9duSuq")   // "password"를 암호화한값
                .authorities("ROLE_USER") // 유저 권한
                .build();
    }

}
