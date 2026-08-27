package com.common.identity.auth.service;

public interface EmailService {

    void sendVerificationEmail(String recipient, String verificationUrl);
}