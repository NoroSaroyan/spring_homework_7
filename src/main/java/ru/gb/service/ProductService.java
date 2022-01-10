package ru.gb.service;

import ru.gb.entity.Product;

import java.util.Optional;


public interface ProductService {

    Optional<Product> findById(Long id);


}
