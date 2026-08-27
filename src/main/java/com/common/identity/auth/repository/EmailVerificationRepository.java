package com.common.identity.auth.repository;

import com.common.identity.auth.model.entity.EmailVerification;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface EmailVerificationRepository extends JpaRepository<EmailVerification, UUID> {

    Optional<EmailVerification> findByTokenHash(String tokenHash);

    void deleteByEmail(String email);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
        SELECT e
        FROM EmailVerification e
        WHERE e.tokenHash = :tokenHash
        """)
    Optional<EmailVerification> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);

}