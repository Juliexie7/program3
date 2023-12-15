package JAC.FSD09.library.controller;

import JAC.FSD09.library.domain.Author;
import JAC.FSD09.library.domain.Category;
import JAC.FSD09.library.dto.AuthorDTO;
import JAC.FSD09.library.dto.CategoryDTO;
import JAC.FSD09.library.exception.IdNotFoundException;
import JAC.FSD09.library.mapper.CategoryMapperHelper;
import JAC.FSD09.library.service.CategoryService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/category")
@SessionAttributes("title")
public class CategoryController {

    private final CategoryService service;
    private final CategoryMapperHelper mapperHelper;

    @Autowired
    public CategoryController(CategoryService service, CategoryMapperHelper mapperHelper) {
        this.service = service;
        this.mapperHelper = mapperHelper;
    }

    @GetMapping("/list")
    public String listCategory(Model theCategorys){
        List<Category> allCategorys = service.getAllCategorys();
        List<CategoryDTO> categoryDTOS = mapperHelper.convertCategoryListToCategoryDTOList(allCategorys);
        theCategorys.addAttribute("categorys", categoryDTOS);
        //return the thymeleaf
        return "list_category";
    }


    @GetMapping("/showFormForAdd")
    public String showFormForAdd(Model theModel){

        theModel.addAttribute("title", "Add Category");
        theModel.addAttribute("category", new CategoryDTO());
        return "category_form";
    }

    @GetMapping("/showFormForUpdate")
    public String showFormForUpdate(@RequestParam("categoryId") Long theId, Model theModel){
        try{
            Category categoryById = service.findCategoryById(theId);
            theModel.addAttribute("title", "Update Category");
            theModel.addAttribute("category", categoryById);
            return "category_form";
        }
        catch (IdNotFoundException exception) {
            theModel.addAttribute("category", new CategoryDTO());
            theModel.addAttribute("title", "Add Category");
            theModel.addAttribute("exceptionMessage", exception.getMessage());
            return "category_form";
        }
    }

    @PostMapping("/upsert")
    public String upsertCategory(@Valid @ModelAttribute("category") CategoryDTO theCategory, BindingResult result){
        if(result.hasErrors()){
            return "category_form";
        }
        Category category = mapperHelper.convertCategoryDTOToCategory(theCategory);
        service.saveCategory(category);

        return "redirect:/category/list";
    }

    @GetMapping("/delete")
    public String delete(@RequestParam("categoryId") Long theId, Model theModel){
        try{
            service.deleteCategoryById(theId);
            return "redirect:/category/list";

        } catch (DataIntegrityViolationException ex) {
            theModel.addAttribute("error", "Cannot delete the author due to existing dependencies.");
            List<Category> categoryList = service.getAllCategorys();
            List<CategoryDTO> categoryDTOList = mapperHelper.convertCategoryListToCategoryDTOList(categoryList);
            theModel.addAttribute("categorys", categoryDTOList);
            return "list_category";
        }
    }

}
