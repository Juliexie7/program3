package JAC.FSD09.library.mapper;

import JAC.FSD09.library.domain.Author;
import JAC.FSD09.library.domain.Book;
import JAC.FSD09.library.dto.AuthorDTO;
import JAC.FSD09.library.dto.BookDTO;
import JAC.FSD09.library.entity.BookEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class BookMapperHelper {

    private final ObjectMapper mapper;

    @Autowired
    public BookMapperHelper(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public List<BookDTO> convertBookListToBookDTOList(List<Book> books){
        List<BookDTO> bookDTOs = new ArrayList<>();
        for(Book temp: books){
            bookDTOs.add(mapper.convertValue(temp, BookDTO.class));
        }

        return bookDTOs;
    }

    public List<Book> convertBookEntityListToBookList(List<BookEntity> bookEntities) {
        List<Book> bookList = new ArrayList<>();
        for (BookEntity temp: bookEntities){
            bookList.add(mapper.convertValue(temp, Book.class));
        }

        return bookList;
    }

    public Book convertBookEntityToBook(BookEntity bookEntity) {
        return mapper.convertValue(bookEntity, Book.class);
    }

    public BookEntity convertBookToBookEntity(Book book){
        return mapper.convertValue(book, BookEntity.class);
    }

    public Book convertBookDTOToBook(BookDTO bookDTO) {
        return mapper.convertValue(bookDTO, Book.class);
    }
    
}
