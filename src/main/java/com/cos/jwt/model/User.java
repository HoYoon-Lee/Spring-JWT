package com.cos.jwt.model;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Data
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private String userName;
    private String password;
    private String roles;

    public List<String> getRoleList(){
        if(!roles.isEmpty() && !roles.isBlank())
            return Arrays.asList(roles.split(", "));
        return new ArrayList<>();
    }
}
