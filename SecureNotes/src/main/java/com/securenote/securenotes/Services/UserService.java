package com.securenote.securenotes.Services;

import com.securenote.securenotes.DTOs.UserDTO;
import com.securenote.securenotes.Entities.Role;
import com.securenote.securenotes.Entities.User;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

import java.util.List;
import java.util.Optional;

public interface UserService {
    void updateUserRole(Long userId, String roleName);

    List<User> getAllUsers();

    UserDTO getUserById(Long id);

    User findByUsername(String username);

    void updateAccountLockStatus(Long userId, boolean status);

    List<Role> getRoles();

    void updateAccountExpiryStatus(Long userId, boolean expire);

    void updateAccountEnabledStatus(Long userId, boolean enabled);

    void updateCredentialsExpiryStatus(Long userId, boolean expire);

    void updatePassword(Long userId, String password);

    void generatePasswordToken(String email);

    void resetPassword(String token, String newPassword);

    Optional<User> findByEmail(String email);

    User registerUser(User newUser);

    GoogleAuthenticatorKey generate2FASecret(Long userId);

    boolean Validate2FASecret(Long userId, int code);

    void enable2FA(Long userId);

    void disable2FA(Long userId);
}