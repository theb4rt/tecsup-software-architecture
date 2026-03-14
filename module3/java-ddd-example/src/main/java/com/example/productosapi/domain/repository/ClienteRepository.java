package com.example.productosapi.domain.repository;

import com.example.productosapi.domain.model.Cliente;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Domain repository interface for Clients.
 */
public interface ClienteRepository {

    Cliente save(Cliente cliente);

    Optional<Cliente> findById(UUID id);

    Optional<Cliente> findByEmail(String email);

    List<Cliente> findAll();

    void deleteById(UUID id);

    boolean existsByEmail(String email);
}
