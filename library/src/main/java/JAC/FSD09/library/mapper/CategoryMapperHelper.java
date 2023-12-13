package JAC.FSD09.library.mapper;

import JAC.FSD09.library.domain.Book;
import JAC.FSD09.library.domain.Category;
import JAC.FSD09.library.dto.BookDTO;
import JAC.FSD09.library.dto.CategoryDTO;
import JAC.FSD09.library.entity.CategoryEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class CategoryMapperHelper {

    private final ObjectMapper mapper;

    @Autowired
    public CategoryMapperHelper(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public List<CategoryDTO> convertCategoryListToCategoryDTOList(List<Category> categorys){
        List<CategoryDTO> categoryDTOs = new ArrayList<>();
        for(Category temp: categorys){
            categoryDTOs.add(mapper.convertValue(temp, CategoryDTO.class));
        }

        return categoryDTOs;
    }

    public List<Category> convertCategoryEntityListToCategoryList(List<CategoryEntity> categoryEntities) {
        List<Category> categoryList = new ArrayList<>();
        for (CategoryEntity temp: categoryEntities){
            categoryList.add(mapper.convertValue(temp, Category.class));
        }
        return categoryList;
    }

    public Category convertCategoryEntityToCategory(CategoryEntity categoryEntity) {
        return mapper.convertValue(categoryEntity, Category.class);
    }

    public CategoryEntity convertCategoryToCategoryEntity(Category category){
        return mapper.convertValue(category, CategoryEntity.class);
    }

    public Category convertCategoryDTOToCategory(CategoryDTO categoryDTO) {
        return mapper.convertValue(categoryDTO, Category.class);
    }
    
}
