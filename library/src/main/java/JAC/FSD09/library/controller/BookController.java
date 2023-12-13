package JAC.FSD09.library.controller;

import JAC.FSD09.library.domain.Author;
import JAC.FSD09.library.domain.Book;
import JAC.FSD09.library.domain.Category;
import JAC.FSD09.library.dto.AuthorDTO;
import JAC.FSD09.library.dto.BookDTO;
import JAC.FSD09.library.dto.CategoryDTO;
import JAC.FSD09.library.exception.IdNotFoundException;
import JAC.FSD09.library.mapper.AuthorMapperHelper;
import JAC.FSD09.library.mapper.BookMapperHelper;
import JAC.FSD09.library.mapper.CategoryMapperHelper;
import JAC.FSD09.library.service.AuthorService;
import JAC.FSD09.library.service.BookService;
import JAC.FSD09.library.service.CategoryService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/book")
@SessionAttributes({"title", "authors", "categorys"})
public class BookController {

    private final BookService service;
    private final AuthorService authorService;
    private final CategoryService categoryService;

    private final BookMapperHelper mapperHelper;
    private final AuthorMapperHelper authorMapperHelper;
    private final CategoryMapperHelper categoryMapperHelper;

    @Autowired
    public BookController(BookService service, AuthorService authorService, CategoryService categoryService, BookMapperHelper mapperHelper, AuthorMapperHelper authorMapperHelper, CategoryMapperHelper categoryMapperHelper) {
        this.service = service;
        this.authorService = authorService;
        this.categoryService = categoryService;
        this.mapperHelper = mapperHelper;
        this.authorMapperHelper = authorMapperHelper;
        this.categoryMapperHelper = categoryMapperHelper;
    }

    @GetMapping("/list")
    public String listBook(Model theBooks){
        List<Book> allBooks = service.getAllBooks();
        List<BookDTO> bookDTOS = mapperHelper.convertBookListToBookDTOList(allBooks);
        theBooks.addAttribute("books", bookDTOS);
        //return the thymeleaf
        return "list_book";
    }

    @GetMapping("/user_list")
    public String userListBook(Model theBooks){
        List<Book> allBooks = service.getAllBooks();
        List<BookDTO> bookDTOS = mapperHelper.convertBookListToBookDTOList(allBooks);
        theBooks.addAttribute("books", bookDTOS);
        //return the thymeleaf
        return "user_book";
    }

    @GetMapping("/showFormForAdd")
    public String showFormForAdd(Model theModel){

        theModel.addAttribute("title", "Add a Book");
        theModel.addAttribute("book", new BookDTO());

        List<Author> allAuthors = authorService.getAllAuthors();
        List<AuthorDTO> authorDTOS = authorMapperHelper.convertAuthorListToAuthorDTOList(allAuthors);
        theModel.addAttribute("authors", authorDTOS);

        List<Category> allCategorys = categoryService.getAllCategorys();
        List<CategoryDTO> categoryDTOS = categoryMapperHelper.convertCategoryListToCategoryDTOList(allCategorys);
        theModel.addAttribute("categorys", categoryDTOS);
        return "book_form";
    }

    @GetMapping("/showFormForUpdate")
    public String showFormForUpdate(@RequestParam("bookId") Long theId, Model theModel){
        try{
            Book bookById = service.findBookById(theId);
            theModel.addAttribute("title", "Update a Book");
            theModel.addAttribute("book", bookById);

            List<Author> allAuthors = authorService.getAllAuthors();
            List<AuthorDTO> authorDTOS = authorMapperHelper.convertAuthorListToAuthorDTOList(allAuthors);
            theModel.addAttribute("authors", authorDTOS);

            List<Category> allCategorys = categoryService.getAllCategorys();
            List<CategoryDTO> categoryDTOS = categoryMapperHelper.convertCategoryListToCategoryDTOList(allCategorys);
            theModel.addAttribute("categorys", categoryDTOS);

            return "book_form";
        }
        catch (IdNotFoundException exception) {
            theModel.addAttribute("book", new BookDTO());
            theModel.addAttribute("author", new AuthorDTO());
            theModel.addAttribute("category", new CategoryDTO());
            theModel.addAttribute("title", "Add a Book");
            theModel.addAttribute("exceptionMessage", exception.getMessage());
            return "book_form";
        }
    }

    @PostMapping("/upsert")
    public String upsertBook(@Valid @ModelAttribute("book") BookDTO theBook, BindingResult result){
        if(result.hasErrors()){
            return "book_form";
        }


        Book book = mapperHelper.convertBookDTOToBook(theBook);
        service.saveBook(book);

        return "redirect:/book/list";
    }

    @GetMapping("/delete")
    public String delete(@RequestParam("bookId") Long theId){
        service.deleteBookById(theId);
        return "redirect:/book/list";
    }

}
