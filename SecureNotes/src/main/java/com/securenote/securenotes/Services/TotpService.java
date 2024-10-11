package com.securenote.securenotes.Services;

import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

public interface TotpService {

    GoogleAuthenticatorKey generateKey();

    String getQrCodeUrl(GoogleAuthenticatorKey secret, String Username);

    boolean VerifyCode(String Secret, int code);
}
