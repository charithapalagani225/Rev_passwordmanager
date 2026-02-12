// Models: User.java, Credential.java, SecurityQuestion.java
package com.revpasswordmanager.model;

public class User {
    private int id;
    private String username;
    private String masterPasswordHash;
    private String name;
    private String email;

    public User(String username, String masterPasswordHash, String name, String email) {
        this.username = username;
        this.masterPasswordHash = masterPasswordHash;
        this.name = name;
        this.email = email;
    }

    public User(int id, String username, String masterPasswordHash, String name, String email) {
        this.id = id;
        this.username = username;
        this.masterPasswordHash = masterPasswordHash;
        this.name = name;
        this.email = email;
    }

    // Getters and setters
    public int getId() { return id; }
    public String getUsername() { return username; }
    public String getMasterPasswordHash() { return masterPasswordHash; }
    public void setMasterPasswordHash(String hash) { this.masterPasswordHash = hash; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}

