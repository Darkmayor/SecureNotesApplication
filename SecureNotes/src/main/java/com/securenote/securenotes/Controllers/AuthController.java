package com.securenote.securenotes.Controllers;

import com.securenote.securenotes.Entities.Role;
import com.securenote.securenotes.Entities.User;
import com.securenote.securenotes.Entities.UserRoles;
import com.securenote.securenotes.Repository.RoleRepository;
import com.securenote.securenotes.Repository.UserRepository;
import com.securenote.securenotes.Services.TotpService;
import com.securenote.securenotes.Services.UserService;
import com.securenote.securenotes.Services.impl.UserDetailsImpl;
import com.securenote.securenotes.Services.impl.UserServiceImpl;
import com.securenote.securenotes.Utils.AuthControllerUtils.LoginRequest;
import com.securenote.securenotes.Utils.AuthControllerUtils.LoginResponse;
import com.securenote.securenotes.Security.jwt.JwtUtils;
import com.securenote.securenotes.Utils.AuthUtil;
import com.securenote.securenotes.Utils.Response.MessageResponse;
import com.securenote.securenotes.Utils.Response.UserInfoResponse;
import com.securenote.securenotes.Utils.SignUpRequest;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private UserService userService;
    @Autowired
    private AuthUtil authUtil;
    @Autowired
    private TotpService totpService;

    @PostMapping("/public/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        try {
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        } catch (AuthenticationException exception) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

//      set the authentication
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        // Collect roles from the UserDetails
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        // Prepare the response body, now including the JWT token directly in the body
        LoginResponse response = new LoginResponse(userDetails.getUsername(), roles, jwtToken);

        // Return the response entity with the JWT token included in the response body
        return ResponseEntity.ok(response);
    }

    @PostMapping("/public/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody
                                              SignUpRequest signUpRequest) {
        if (userRepository.existsByUserName(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                passwordEncoder.encode(signUpRequest.getPassword())
        );

        Set<String> strRoles = signUpRequest.getRole();
        Role role;

        if (strRoles == null || strRoles.isEmpty()) {
            role = roleRepository.findByRoleName(UserRoles.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        } else {
            String roleStr = strRoles.iterator().next();
            if (roleStr.equals("admin")) {
                role = roleRepository.findByRoleName(UserRoles.ROLE_ADMIN)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            } else {
                role = roleRepository.findByRoleName(UserRoles.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            }

            user.setAccountNonLocked(true);
            user.setAccountNonExpired(true);
            user.setCredentialsNonExpired(true);
            user.setEnabled(true);
            user.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
            user.setAccountExpiryDate(LocalDate.now().plusYears(1));
            user.setTwoFactorEnabled(false);
            user.setSignUpMethod("email");
        }
        user.setRole(role);
        userRepository.save(user);

        return ResponseEntity.ok(
                new MessageResponse("User registered successfully!")
        );
    }

    @GetMapping("/user")
    public ResponseEntity<?> getUsers(@AuthenticationPrincipal
                                          UserDetails userDetails) {
        //fetch user
        User user = userService.findByUsername(userDetails.getUsername());

        //find roles associated with the current user
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority()).
                collect(Collectors.toList());

        UserInfoResponse userInfoResponse = new UserInfoResponse(
        user.getUserId(),
        user.getUserName(),
        user.getEmail(),
        user.isAccountNonLocked(),
        user.isAccountNonExpired(),
        user.isCredentialsNonExpired(),
        user.isEnabled(),
        user.getCredentialsExpiryDate(),
        user.getAccountExpiryDate(),
        user.isTwoFactorEnabled(),
        roles
        );

        return ResponseEntity.ok().body(userInfoResponse);
    }

    @GetMapping("/username")
    public ResponseEntity<String> getUsername(@AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        return (username != null) ? ResponseEntity.ok(username) : ResponseEntity.notFound().build();
    }

    @PostMapping("/public/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email){
        try{
            userService.generatePasswordToken(email);
            return ResponseEntity.ok(new MessageResponse("Reset password Link send!"));
        }
        catch (Exception e){
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new MessageResponse("Error: Email is not found!"));
        }

    }

    @PostMapping("/public/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token,
    @RequestParam String newPassword){
        try{
            userService.resetPassword(token,newPassword);
            return ResponseEntity.ok(new MessageResponse("Password reset successfully!"));
        }catch(Exception e){
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse("Password reset failed!"));
        }

    }

    @PostMapping("/enable-2fa")
    public ResponseEntity<String> enable2FA(){
        Long userId = authUtil.LoggedInUserId();
        //generate 2fa
        GoogleAuthenticatorKey secret = userService.generate2FASecret(userId);
        //qr code
        String QrCodeUrl = totpService.getQrCodeUrl(secret , userService.getUserById(userId).getUserName());
        return new ResponseEntity<>(QrCodeUrl, HttpStatus.OK);
    }

    @PostMapping("/disable-2fa")
    public ResponseEntity<String> disable2FA(){
        Long userId = authUtil.LoggedInUserId();
        userService.disable2FA(userId);
        return new ResponseEntity<>("2FA disabled successfully",HttpStatus.OK);
    }

    @PostMapping("/verify-2fa")
    public ResponseEntity<String> verify2FA(@RequestParam int code){
        Long userId = authUtil.LoggedInUserId();
        boolean isValid = userService.Validate2FASecret(userId,code);
        if(isValid){
            userService.enable2FA(userId);
            return ResponseEntity.ok("2FA verified successfully");
        }else{
            return new ResponseEntity<>("2FA verification failed - Invalid 2FA Code", HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/user/2fa-status")
    public ResponseEntity<?> verify2FAStatus(){
        User user = authUtil.LoggedInUser();
        if(user != null){
            return ResponseEntity.ok(Map.of("is2faEnabled"
                    , user.isTwoFactorEnabled()));
        }else{
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    "User not found"
            );
        }
    }

    @PostMapping("/public/verify-2fa-login")
    public ResponseEntity<String> verify2FAStatus(@RequestParam int code,
                                                  @RequestParam String jwtToken){

        String username = jwtUtils.getUserNameFromJwtToken(jwtToken);
        User user = userService.findByUsername(username);
        boolean isValid = userService.Validate2FASecret(user.getUserId(),code);
        if(isValid){
            return ResponseEntity.ok("2FA verified successfully");
        }else{
            return new ResponseEntity<>("2FA verification failed - Invalid 2FA Code", HttpStatus.UNAUTHORIZED);
        }
    }

}
