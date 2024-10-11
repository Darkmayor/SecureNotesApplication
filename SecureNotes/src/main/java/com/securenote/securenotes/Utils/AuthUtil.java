package com.securenote.securenotes.Utils;

import com.securenote.securenotes.Entities.User;
import com.securenote.securenotes.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class AuthUtil {

    @Autowired
    UserRepository userRepository;

    public Long LoggedInUserId(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = userRepository.findByUserName(authentication.getName()).orElseThrow(
                () -> new RuntimeException("User not found")
        );
        return user.getUserId();
    }

    public User LoggedInUser(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = userRepository.findByUserName(authentication.getName()).orElseThrow(
                () -> new RuntimeException("User not found")
        );
        return user;
    }

}
