package JAC.FSD09.library.service;

import JAC.FSD09.library.domain.Author;
import JAC.FSD09.library.exception.IdNotFoundException;

import java.util.List;

public interface AuthorService {

    List<Author> getAllAuthors();

    Long saveAuthor(Author author);

    Author findAuthorById(Long authorId) throws IdNotFoundException;

    void deleteAuthorById(Long authorId);

}
