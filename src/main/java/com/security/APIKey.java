package com.security;

import io.quarkus.hibernate.orm.panache.PanacheEntity;

import javax.persistence.Column;
import javax.persistence.Entity;

@Entity
public class APIKey extends PanacheEntity {

    @Column
    public String apiKey;

    @Column
    public String role;

    public APIKey(String apiKey, String role) {
        this.apiKey = apiKey;
        this.role = role;
    }

    public APIKey() {
    }
}

