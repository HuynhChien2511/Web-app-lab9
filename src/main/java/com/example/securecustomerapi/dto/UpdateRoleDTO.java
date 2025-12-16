package com.example.securecustomerapi.dto;

import jakarta.validation.constraints.NotBlank;

public class UpdateRoleDTO {

    @NotBlank
    private String role;

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
