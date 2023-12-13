package JAC.FSD09.library.controller;

import JAC.FSD09.library.domain.Author;
import JAC.FSD09.library.dto.AuthorDTO;
import JAC.FSD09.library.exception.IdNotFoundException;
import JAC.FSD09.library.mapper.AuthorMapperHelper;
import JAC.FSD09.library.service.AuthorService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/author")
@SessionAttributes("title")
public class AuthorController {

    private final AuthorService service;
    private final AuthorMapperHelper mapperHelper;

    @Autowired
    public AuthorController(AuthorService service, AuthorMapperHelper mapperHelper) {
        this.service = service;
        this.mapperHelper = mapperHelper;
    }


    @GetMapping("/list")
    public String listAuthor(Model theAuthors){
        List<Author> allAuthors = service.getAllAuthors();
        List<AuthorDTO> authorDTOS = mapperHelper.convertAuthorListToAuthorDTOList(allAuthors);
        theAuthors.addAttribute("authors", authorDTOS);
        //return the thymeleaf
        return "list_author";
    }


    @GetMapping("/showFormForAdd")
    public String showFormForAdd(Model theModel){

        theModel.addAttribute("title", "Add an Author");
        theModel.addAttribute("author", new AuthorDTO());
        return "author_form";
    }

    @GetMapping("/showFormForUpdate")
    public String showFormForUpdate(@RequestParam("authorId") Long theId, Model theModel){
        try{
            Author authorById = service.findAuthorById(theId);
            theModel.addAttribute("title", "Update an Author");
            theModel.addAttribute("author", authorById);
            return "author_form";
        }
        catch (IdNotFoundException exception) {
            theModel.addAttribute("author", new AuthorDTO());
            theModel.addAttribute("title", "Add an Author");
            theModel.addAttribute("exceptionMessage", exception.getMessage());
            return "author_form";
        }
    }

    @PostMapping("/upsert")
    public String upsertAuthor(@Valid @ModelAttribute("author") AuthorDTO theAuthor, BindingResult result){
        if(result.hasErrors()){
            return "author_form";
        }
        Author author = mapperHelper.convertAuthorDTOToAuthor(theAuthor);
        service.saveAuthor(author);

        return "redirect:/author/list";
    }

    @GetMapping("/delete")
    public String delete(@RequestParam("authorId") Long theId){
        service.deleteAuthorById(theId);
        return "redirect:/author/list";
    }

}
