package com.revpasswordmanager.dao;

import com.revpasswordmanager.model.Credential;

import java.util.List;

public interface ICredentialDao {
    void addCredential(Credential credential);

    List<Credential> getCredentialsByUserId(int userId);

    Credential getCredentialById(int id, int userId);

    void updateCredential(Credential credential);

    void deleteCredential(int id, int userId);

    List<Credential> searchCredentialsByAccountName(int userId, String accountName);
}
