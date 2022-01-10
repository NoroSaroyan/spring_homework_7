package ru.gb.repository;

import org.springframework.data.repository.CrudRepository;
import ru.gb.entity.Role;

import java.util.Collection;

public interface RoleRepository extends CrudRepository<Role, Long> {


}
