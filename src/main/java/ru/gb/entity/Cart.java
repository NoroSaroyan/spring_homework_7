package ru.gb.entity;

import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.beans.factory.annotation.Value;

import javax.persistence.*;
import java.util.List;


@Entity
@Table(name = "cart")

@FieldDefaults(level = AccessLevel.PRIVATE)
@Data

public class Cart {
    @Id
    @GeneratedValue
    protected long id;
    protected long countProduct;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private Cart cart;

    @ManyToMany
    @JoinTable(name = "cart_products",
            joinColumns = @JoinColumn(name = "cart_id"),
            inverseJoinColumns = @JoinColumn(name = "product_id"))
    List<Product> products;

    public Cart() {
    }

    public Cart(@Value("id") long id,
                @Value("countProduct") long countProduct) {
        this.id = id;
        this.countProduct = countProduct;
    }

}