package com.example.productosapi.infrastructure.rest.controller;

import com.example.productosapi.application.usecase.CreateClienteUseCase;
import com.example.productosapi.application.usecase.DeleteClienteUseCase;
import com.example.productosapi.application.usecase.GetClienteUseCase;
import com.example.productosapi.application.usecase.UpdateClienteUseCase;
import com.example.productosapi.domain.model.Cliente;
import com.example.productosapi.infrastructure.persistence.mapper.ClienteMapper;
import com.example.productosapi.infrastructure.rest.dto.*;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * REST controller for Client operations
 */
@RestController
@RequestMapping("/api/clientes")
@RequiredArgsConstructor
public class ClienteController {

    private final CreateClienteUseCase createClienteUseCase;
    private final GetClienteUseCase getClienteUseCase;
    private final UpdateClienteUseCase updateClienteUseCase;
    private final DeleteClienteUseCase deleteClienteUseCase;
    private final ClienteMapper mapper;

    /**
     * Creates a new client
     */
    @PostMapping
    public ResponseEntity<ClienteResponse> crearCliente(@Valid @RequestBody ClienteRequest request) {
        Cliente cliente = mapper.toDomain(request);
        Cliente creado = createClienteUseCase.execute(cliente);
        return new ResponseEntity<>(mapper.toResponse(creado), HttpStatus.CREATED);
    }

    /**
     * Retrieves a client by their ID
     */
    @GetMapping("/{id}")
    public ResponseEntity<ClienteResponse> obtenerCliente(@PathVariable UUID id) {
        Cliente cliente = getClienteUseCase.executeById(id);
        return ResponseEntity.ok(mapper.toResponse(cliente));
    }

    /**
     * Retrieves a client by their email
     */
    @GetMapping("/email/{email}")
    public ResponseEntity<ClienteResponse> obtenerClientePorEmail(@PathVariable String email) {
        Cliente cliente = getClienteUseCase.executeByEmail(email);
        return ResponseEntity.ok(mapper.toResponse(cliente));
    }

    /**
     * Retrieves all clients
     */
    @GetMapping
    public ResponseEntity<List<ClienteResponse>> obtenerTodosLosClientes() {
        List<Cliente> clientes = getClienteUseCase.executeAll();
        return ResponseEntity.ok(mapper.toResponseList(clientes));
    }

    /**
     * Updates an existing client
     */
    @PutMapping("/{id}")
    public ResponseEntity<ClienteResponse> actualizarCliente(
            @PathVariable UUID id,
            @Valid @RequestBody ClienteUpdateRequest request) {

        Cliente actualizado = updateClienteUseCase.execute(
                id,
                request.getNombre(),
                request.getApellido(),
                request.getEmail(),
                request.getTelefono(),
                request.getDireccion()
        );

        return ResponseEntity.ok(mapper.toResponse(actualizado));
    }

    /**
     * Updates the active status of a client
     */
    @PatchMapping("/{id}/estado")
    public ResponseEntity<ClienteResponse> actualizarEstadoCliente(
            @PathVariable UUID id,
            @Valid @RequestBody EstadoUpdateRequest request) {

        Cliente actualizado = updateClienteUseCase.executeStateUpdate(id, request.getActivo());
        return ResponseEntity.ok(mapper.toResponse(actualizado));
    }

    /**
     * Deletes a client
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> eliminarCliente(@PathVariable UUID id) {
        deleteClienteUseCase.execute(id);
        return ResponseEntity.noContent().build();
    }
}
