package com.common.identity.auth.service;

import com.common.identity.auth.model.dto.PasswordResetRequestedEventDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
public class PasswordResetEmailListener {

    private final EmailService emailService;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handle(PasswordResetRequestedEventDto event) {
        emailService.sendPasswordResetEmail(event.email(), event.resetUrl());
    }
}