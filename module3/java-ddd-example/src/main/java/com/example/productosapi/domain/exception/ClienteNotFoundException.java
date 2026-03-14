package com.example.productosapi.domain.exception;

import java.util.UUID;

/**
 * Domain exception for when a client is not found
 */
public class ClienteNotFoundException extends BusinessException {

    public ClienteNotFoundException(UUID id) {
        super("Client not found with ID: " + id);
    }

    public ClienteNotFoundException(String email) {
        super("Client not found with email: " + email);
    }
}
