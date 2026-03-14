package com.example.productosapi.infrastructure.persistence.repository;

import com.example.productosapi.infrastructure.persistence.entity.ClienteEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * JPA repository for ClienteEntity
 */
public interface ClienteJpaRepository extends JpaRepository<ClienteEntity, UUID> {

    Optional<ClienteEntity> findByEmail(String email);

    boolean existsByEmail(String email);
}
