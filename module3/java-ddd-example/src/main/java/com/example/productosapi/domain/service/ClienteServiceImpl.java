package com.example.productosapi.domain.service;

import com.example.productosapi.domain.exception.BusinessException;
import com.example.productosapi.domain.exception.ClienteNotFoundException;
import com.example.productosapi.domain.model.Cliente;
import com.example.productosapi.domain.repository.ClienteRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Domain service implementation for Clients
 */
@Service
@RequiredArgsConstructor
@Transactional
public class ClienteServiceImpl implements ClienteService {

    private final ClienteRepository clienteRepository;

    @Override
    public Cliente crearCliente(Cliente cliente) {
        if (clienteRepository.existsByEmail(cliente.getEmail())) {
            throw new BusinessException("A client already exists with email: " + cliente.getEmail());
        }
        return clienteRepository.save(cliente);
    }

    @Override
    @Transactional(readOnly = true)
    public Cliente obtenerClientePorId(UUID id) {
        return clienteRepository.findById(id)
                .orElseThrow(() -> new ClienteNotFoundException(id));
    }

    @Override
    @Transactional(readOnly = true)
    public Cliente obtenerClientePorEmail(String email) {
        return clienteRepository.findByEmail(email)
                .orElseThrow(() -> new ClienteNotFoundException(email));
    }

    @Override
    @Transactional(readOnly = true)
    public List<Cliente> obtenerTodosLosClientes() {
        return clienteRepository.findAll();
    }

    @Override
    public Cliente actualizarCliente(UUID id, String nombre, String apellido,
                                     String email, String telefono, String direccion) {
        Cliente clienteExistente = obtenerClientePorId(id);

        if (!clienteExistente.getEmail().equals(email) && clienteRepository.existsByEmail(email)) {
            throw new BusinessException("A client already exists with email: " + email);
        }

        Cliente clienteActualizado = clienteExistente.actualizar(nombre, apellido, email, telefono, direccion);
        return clienteRepository.save(clienteActualizado);
    }

    @Override
    public Cliente actualizarEstadoCliente(UUID id, Boolean activo) {
        Cliente clienteExistente = obtenerClientePorId(id);
        Cliente clienteActualizado = clienteExistente.cambiarEstado(activo);
        return clienteRepository.save(clienteActualizado);
    }

    @Override
    public void eliminarCliente(UUID id) {
        if (!clienteRepository.findById(id).isPresent()) {
            throw new ClienteNotFoundException(id);
        }
        clienteRepository.deleteById(id);
    }
}
