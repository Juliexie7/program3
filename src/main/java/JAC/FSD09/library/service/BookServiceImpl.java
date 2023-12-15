package JAC.FSD09.library.service;

import JAC.FSD09.library.domain.Book;
import JAC.FSD09.library.entity.BookEntity;
import JAC.FSD09.library.exception.IdNotFoundException;
import JAC.FSD09.library.mapper.BookMapperHelper;
import JAC.FSD09.library.repository.BookRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class BookServiceImpl implements BookService{
    
    private final BookRepository bookRepository;
    private final BookMapperHelper mapperHelper;

    @Autowired
    public BookServiceImpl(BookRepository bookRepository, BookMapperHelper mapperHelper) {
        this.bookRepository = bookRepository;
        this.mapperHelper = mapperHelper;
    }

    @Override
    public List<Book> getAllBooks() {
        List<BookEntity> all = bookRepository.findAll();
        return mapperHelper.convertBookEntityListToBookList(all);
    }

    @Override
    public Long saveBook(Book book) {

        BookEntity bookEntity = mapperHelper.convertBookToBookEntity(book);
        BookEntity save = bookRepository.save(bookEntity);
        return save.getBook_id();
    }

    @Override
    public Book findBookById(Long bookId) throws IdNotFoundException {
        Optional<BookEntity> byId = bookRepository.findById(bookId);

        if(byId.isPresent()){
            BookEntity bookEntity = byId.get();
            return mapperHelper.convertBookEntityToBook(bookEntity);
        }

        throw new IdNotFoundException("There is no book by id " + bookId);
    }

    @Override
    public void deleteBookById(Long bookId) {
        bookRepository.deleteById(bookId);
    }
}
