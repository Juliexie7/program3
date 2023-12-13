package JAC.FSD09.library.service;

import JAC.FSD09.library.domain.Category;
import JAC.FSD09.library.entity.CategoryEntity;
import JAC.FSD09.library.exception.IdNotFoundException;
import JAC.FSD09.library.mapper.CategoryMapperHelper;
import JAC.FSD09.library.repository.CategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class CategoryServiceImpl implements CategoryService {
    
    private final CategoryRepository categoryRepository;
    private final CategoryMapperHelper mapperHelper;

    @Autowired
    public CategoryServiceImpl(CategoryRepository categoryRepository, CategoryMapperHelper mapperHelper) {
        this.categoryRepository = categoryRepository;
        this.mapperHelper = mapperHelper;
    }

    @Override
    public List<Category> getAllCategorys() {
        List<CategoryEntity> all = categoryRepository.findAll();
        return mapperHelper.convertCategoryEntityListToCategoryList(all);
    }

    @Override
    public Long saveCategory(Category category) {
        CategoryEntity categoryEntity = mapperHelper.convertCategoryToCategoryEntity(category);
        CategoryEntity save = categoryRepository.save(categoryEntity);
        return save.getCategory_id();
    }

    @Override
    public Category findCategoryById(Long categoryId) throws IdNotFoundException {
        Optional<CategoryEntity> byId = categoryRepository.findById(categoryId);

        if(byId.isPresent()){
            CategoryEntity categoryEntity = byId.get();
            return mapperHelper.convertCategoryEntityToCategory(categoryEntity);
        }

        throw new IdNotFoundException("There is no category by id " + categoryId);
    }

    @Override
    public void deleteCategoryById(Long CategoryId) {
        categoryRepository.deleteById(CategoryId);
    }
}
