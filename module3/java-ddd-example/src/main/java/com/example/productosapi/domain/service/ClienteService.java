package com.example.productosapi.domain.service;

import com.example.productosapi.domain.model.Cliente;

import java.util.List;
import java.util.UUID;

/**
 * Domain service interface for Clients
 */
public interface ClienteService {

    Cliente crearCliente(Cliente cliente);

    Cliente obtenerClientePorId(UUID id);

    Cliente obtenerClientePorEmail(String email);

    List<Cliente> obtenerTodosLosClientes();

    Cliente actualizarCliente(UUID id, String nombre, String apellido,
                              String email, String telefono, String direccion);

    Cliente actualizarEstadoCliente(UUID id, Boolean activo);

    void eliminarCliente(UUID id);
}
