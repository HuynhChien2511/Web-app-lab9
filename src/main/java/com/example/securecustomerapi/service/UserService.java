package com.example.securecustomerapi.service;

import com.example.securecustomerapi.dto.*;

public interface UserService {
    
    LoginResponseDTO login(LoginRequestDTO loginRequest);
    
    UserResponseDTO register(RegisterRequestDTO registerRequest);
    
    UserResponseDTO getCurrentUser(String username);

    void changePassword(String username, ChangePasswordDTO dto);

    String initiateForgotPassword(ForgotPasswordRequestDTO dto);

    void resetPassword(ResetPasswordDTO dto);

    UserResponseDTO updateProfile(String username, UpdateProfileDTO dto);

    void deleteAccount(String username, String password);

    java.util.List<UserResponseDTO> getAllUsers();

    UserResponseDTO updateUserRole(Long userId, String role);

    UserResponseDTO toggleUserStatus(Long userId);
}
