package com.example.productosapi.application.usecase;

import com.example.productosapi.domain.service.ClienteService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Use case for deleting a client
 */
@Component
@RequiredArgsConstructor
public class DeleteClienteUseCase {

    private final ClienteService clienteService;

    public void execute(UUID id) {
        clienteService.eliminarCliente(id);
    }
}
