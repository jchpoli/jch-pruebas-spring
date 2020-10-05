package com.platzi.market.persistence;

import com.platzi.market.domain.Product;
import com.platzi.market.domain.repository.ProductRepository;
import com.platzi.market.persistence.crud.ProductoCrudRepository;
import com.platzi.market.persistence.entity.Producto;
import com.platzi.market.persistence.mapper.ProductMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public class ProductoRepository implements ProductRepository {

    @Autowired
    private ProductoCrudRepository productoCrudRepository;

    @Autowired
    private ProductMapper mapper;

    @Override
    public List<Product> getAll() {
        return mapper.toProducts((List<Producto>) productoCrudRepository.findAll());
    }

    @Override
    public Optional<List<Product>> getByCategory(int categoryId) {
        return Optional.of(
                mapper.toProducts(productoCrudRepository.findByIdCategoriaOrderByNombreAsc(categoryId))
        );
    }

    @Override
    public Optional<List<Product>> getScarseProducts(int quantity) {
        return productoCrudRepository.findByCantidadStockLessThanAndEstado(quantity, true)
                .map(prods-> mapper.toProducts(prods));
    }

    @Override
    public Optional<Product> getProduct(int productId) {
        return productoCrudRepository.findById(productId)
                .map(prod-> mapper.toProduct(prod));
    }

    @Override
    public Product save(Product product) {

        return mapper.toProduct(
                productoCrudRepository.save(mapper.toProducto(product))
        );
    }

    @Override
    public void delete(int productId) {
        productoCrudRepository.deleteById(productId);
    }

}
