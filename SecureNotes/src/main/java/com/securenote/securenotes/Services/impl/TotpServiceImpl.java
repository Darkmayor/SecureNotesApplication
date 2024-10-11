package com.securenote.securenotes.Services.impl;

import com.securenote.securenotes.Services.TotpService;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class TotpServiceImpl implements TotpService {

    private final GoogleAuthenticator authenticator;

    public TotpServiceImpl() {
        this.authenticator = new GoogleAuthenticator();
    }

    @Override
    public GoogleAuthenticatorKey generateKey() {
        return authenticator.createCredentials();
    }

    @Override
    public String getQrCodeUrl(GoogleAuthenticatorKey secret, String Username){
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL(
                "Secure Notes Application",
                Username,
                secret
        );
    }
    @Override
    public boolean VerifyCode(String Secret, int code){
        return authenticator.authorize(Secret, code);
    }

}
