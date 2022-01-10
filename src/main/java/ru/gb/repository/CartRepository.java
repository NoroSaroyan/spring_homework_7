package ru.gb.repository;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ru.gb.entity.Cart;

import javax.transaction.Transactional;

@Repository
@Transactional
public interface CartRepository extends PagingAndSortingRepository<Cart, Long> {

    @Query ("select c from Cart as c ")
    Iterable<Cart> findAll();

    @Modifying
    @Query(value = "insert into carts(countProduct, productID) values (:countProduct, :id)", nativeQuery = true)
    Cart saveProductToCart(@Param("id") long id, @Param("countProduct") long countProduct);

}