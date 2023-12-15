package JAC.FSD09.library.service;

import JAC.FSD09.library.domain.Category;
import JAC.FSD09.library.exception.IdNotFoundException;

import java.util.List;

public interface CategoryService {

    List<Category> getAllCategorys();

    Long saveCategory(Category category);

    Category findCategoryById(Long categoryId) throws IdNotFoundException;

    void deleteCategoryById(Long categoryId);
}
