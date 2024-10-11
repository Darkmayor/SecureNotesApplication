package com.securenote.securenotes.Services.impl;

import com.securenote.securenotes.DTOs.UserDTO;
import com.securenote.securenotes.Entities.PasswordResetToken;
import com.securenote.securenotes.Entities.Role;
import com.securenote.securenotes.Entities.User;
import com.securenote.securenotes.Entities.UserRoles;
import com.securenote.securenotes.Repository.PasswordResetTokenRepository;
import com.securenote.securenotes.Repository.RoleRepository;
import com.securenote.securenotes.Repository.UserRepository;
import com.securenote.securenotes.Services.TotpService;
import com.securenote.securenotes.Services.UserService;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailService emailService;

    private final TotpService tottpService;

    @Value("${frontend-uri}")
    String frontendUrl;


    @Override
    public void updateUserRole(Long userId, String roleName) {
        User user = userRepository.findById(userId).orElseThrow(
                ()-> new RuntimeException("User not found")
        );
        UserRoles userrole = UserRoles.valueOf(roleName);
        Role role = roleRepository.findByRoleName(userrole).orElseThrow(
                ()-> new RuntimeException("No Role found with name " + userrole)
        );
        user.setRole(role);
        userRepository.save(user);
    }

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public UserDTO getUserById(Long id) {
        User user = userRepository.findById(id).orElseThrow(
                ()-> new UsernameNotFoundException("No User found with the id" + id)
        );
        return convertToDto(user);
    }

    @Override
    public User findByUsername(String username) {
        User user = userRepository.findByUserName(username).orElseThrow(
                ()-> new UsernameNotFoundException("No User found with the username" + username)
        );
        return user;
    }

    private UserDTO convertToDto(User user) {
        return new UserDTO(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.getTwoFactorSecret(),
                user.isTwoFactorEnabled(),
                user.getSignUpMethod(),
                user.getRole(),
                user.getCreatedDate(),
                user.getUpdatedDate()
        );
    }

    @Override
    public void updatePassword(Long userId, String password) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            user.setPassword(passwordEncoder.encode(password));
            userRepository.save(user);
        } catch (Exception e) {
            throw new RuntimeException("Failed to update password");
        }
    }

    @Override
    public void updateAccountLockStatus(Long userId, boolean lock) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setAccountNonLocked(!lock);
        userRepository.save(user);
    }

    @Override
    public List<Role> getRoles() {
        return roleRepository.findAll();
    }

    @Override
    public void updateAccountExpiryStatus(Long userId, boolean expire) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setAccountNonExpired(!expire);
        userRepository.save(user);
    }

    @Override
    public void updateAccountEnabledStatus(Long userId, boolean enabled) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setEnabled(enabled);
        userRepository.save(user);
    }

    @Override
    public void updateCredentialsExpiryStatus(Long userId, boolean expire) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setCredentialsNonExpired(!expire);
        userRepository.save(user);
    }

    @Override
    public void generatePasswordToken(String email){
        User user = userRepository.findByEmail(email).orElseThrow(
                ()-> new RuntimeException("User not found")
        );
        String token = UUID.randomUUID().toString();
        Instant expiryDate = Instant.now().plus(24, ChronoUnit.HOURS);
        PasswordResetToken resetToken = new PasswordResetToken(expiryDate , token, user);
        passwordResetTokenRepository.save(resetToken);

        String reseturl = frontendUrl +"/reset-password?token="+token;
        //send email to user
        emailService.sendPasswordResetEmail(user.getEmail(), reseturl);
    }

    @Override
    public void resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token)
                .orElseThrow( ()-> new RuntimeException("Invalid token")
        );
        if(resetToken.isUsed()){
            throw new RuntimeException("Reset token is Already used");
        }
        if(resetToken.getExpiryDate().isBefore(Instant.now())){
            throw new RuntimeException("Reset token is Expired");
        }

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        resetToken.setUsed(true);
        passwordResetTokenRepository.save(resetToken);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public User registerUser(User newUser) {
        if(newUser.getPassword()!= null){
            newUser.setPassword(passwordEncoder.encode(newUser.getPassword()));
        }
        userRepository.save(newUser);
        return newUser;
    }

//    MFA methods

    @Override
    public GoogleAuthenticatorKey generate2FASecret(Long userId){
        User user = userRepository.findById(userId).orElseThrow(
                () -> new RuntimeException("User not found")
        );
        GoogleAuthenticatorKey key = tottpService.generateKey();
        user.setTwoFactorSecret(key.getKey());
        userRepository.save(user);
        return key;
    }

    @Override
    public boolean Validate2FASecret(Long userId, int code){
        User user = userRepository.findById(userId).orElseThrow(
                () -> new RuntimeException("User not found")
        );
        return tottpService.VerifyCode(user.getTwoFactorSecret(),code);
    }

    @Override
    public void enable2FA(Long userId){
        User user = userRepository.findById(userId).orElseThrow(
                () -> new RuntimeException("User not found")
        );
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
    }

    @Override
    public void disable2FA(Long userId){

        User user = userRepository.findById(userId).orElseThrow(
                () -> new RuntimeException("User not found")
        );
        user.setTwoFactorEnabled(false);
        userRepository.save(user);
    }


}
