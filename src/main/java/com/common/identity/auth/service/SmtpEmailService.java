package com.common.identity.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SmtpEmailService implements EmailService {

    private final JavaMailSender mailSender;

    @Value("${app.email.from}")
    private String from;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    @Override
    public void sendVerificationEmail(String recipient, String verificationUrl) {

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(recipient);
        message.setSubject("Verify your email");
        message.setText(
                """
                Welcome!
                Please verify your email by clicking the link below:
                %s
                This link expires in 5 minutes.
                If you did not create this account, you can safely ignore this email.
                """.formatted(verificationUrl)
        );

        mailSender.send(message);
    }

    @Override
    public void sendPasswordResetEmail(String recipient, String resetUrl) {

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(recipient);
        message.setSubject("Reset your password");
        message.setText("""
            We received a request to reset your password.
            Click the link below to choose a new password: %s
            This link expires in 15 minutes.
            If you did not request a password reset,
            you can safely ignore this email.
            """.formatted(resetUrl));

        mailSender.send(message);
    }
}