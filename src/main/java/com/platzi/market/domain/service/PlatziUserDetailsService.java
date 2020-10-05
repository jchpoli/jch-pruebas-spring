package com.platzi.market.domain.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class PlatziUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //Como la contraseña no esta cifrada se agrega {noop}
        //Aqui debería ir a la base de datos autenticado por Auth0
        return new User("jonathan", "{noop}platzi", new ArrayList<>());
    }
}
