package com.example.productosapi.application.usecase;

import com.example.productosapi.domain.model.Cliente;
import com.example.productosapi.domain.service.ClienteService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Use case for updating a client
 */
@Component
@RequiredArgsConstructor
public class UpdateClienteUseCase {

    private final ClienteService clienteService;

    public Cliente execute(UUID id, String nombre, String apellido,
                           String email, String telefono, String direccion) {
        return clienteService.actualizarCliente(id, nombre, apellido, email, telefono, direccion);
    }

    public Cliente executeStateUpdate(UUID id, Boolean activo) {
        return clienteService.actualizarEstadoCliente(id, activo);
    }
}
