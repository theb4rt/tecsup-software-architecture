package com.example.productosapi.domain.model;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Domain entity representing a Cliente.
 * Follows DDD immutability principles.
 */
@Getter
@ToString
@Builder
public class Cliente {
    private final UUID id;
    private final String nombre;
    private final String apellido;
    private final String email;
    private final String telefono;
    private final String direccion;
    private final Boolean activo;
    private final LocalDateTime fechaCreacion;
    private final LocalDateTime fechaActualizacion;

    public Cliente actualizar(String nombre, String apellido, String email,
                              String telefono, String direccion) {
        return Cliente.builder()
                .id(this.id)
                .nombre(nombre)
                .apellido(apellido)
                .email(email)
                .telefono(telefono)
                .direccion(direccion)
                .activo(this.activo)
                .fechaCreacion(this.fechaCreacion)
                .fechaActualizacion(LocalDateTime.now())
                .build();
    }

    public Cliente cambiarEstado(Boolean activo) {
        return Cliente.builder()
                .id(this.id)
                .nombre(this.nombre)
                .apellido(this.apellido)
                .email(this.email)
                .telefono(this.telefono)
                .direccion(this.direccion)
                .activo(activo)
                .fechaCreacion(this.fechaCreacion)
                .fechaActualizacion(LocalDateTime.now())
                .build();
    }
}
