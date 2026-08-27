package com.common.identity.auth.service;

import com.common.identity.auth.model.dto.EmailVerificationRequestDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
public class EmailVerificationEmailListener {

    private final EmailService emailService;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handle(EmailVerificationRequestDto event) {

        emailService.sendVerificationEmail(event.email(), event.verificationUrl());
    }
}