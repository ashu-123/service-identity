package com.common.identity.refresh.repository;

import com.common.identity.refresh.model.entity.RefreshToken;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
       SELECT r
       FROM RefreshToken r
       WHERE r.tokenHash = :tokenHash
       """)
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    List<RefreshToken> findAllByFamilyId(UUID familyId);

    List<RefreshToken> findAllByUserId(Long userId);

    @Modifying
    @Query("""
        UPDATE RefreshToken r
        SET r.revokedAt = :revokedAt
        WHERE r.userId = :userId
          AND r.revokedAt IS NULL
        """)
    int revokeAllByUserId(@Param("userId") Long userId, @Param("revokedAt") Instant revokedAt);

}