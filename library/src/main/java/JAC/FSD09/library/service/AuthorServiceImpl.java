package JAC.FSD09.library.service;

import JAC.FSD09.library.domain.Author;
import JAC.FSD09.library.entity.AuthorEntity;
import JAC.FSD09.library.exception.IdNotFoundException;
import JAC.FSD09.library.mapper.AuthorMapperHelper;
import JAC.FSD09.library.repository.AuthorRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class AuthorServiceImpl implements AuthorService{

    private final AuthorRepository authorRepository;

    private final AuthorMapperHelper mapperHelper;

    @Autowired
    public AuthorServiceImpl(AuthorRepository authorRepository, AuthorMapperHelper mapperHelper) {
        this.authorRepository = authorRepository;
        this.mapperHelper = mapperHelper;
    }

    @Override
    public List<Author> getAllAuthors() {
        List<AuthorEntity> all = authorRepository.findAll();
        return mapperHelper.convertAuthorEntityListToAuthorList(all);
    }

    @Override
    public Long saveAuthor(Author author) {
        AuthorEntity authorEntity = mapperHelper.convertAuthorToAuthorEntity(author);
        AuthorEntity save = authorRepository.save(authorEntity);
        return save.getAuthor_id();
    }

    @Override
    public Author findAuthorById(Long authorId) throws IdNotFoundException {
        Optional<AuthorEntity> byId = authorRepository.findById(authorId);

        if(byId.isPresent()){
            AuthorEntity authorEntity = byId.get();
            return mapperHelper.convertAuthorEntityToAuthor(authorEntity);
        }

        throw new IdNotFoundException("There is no author by id " + authorId);
    }

    @Override
    public void deleteAuthorById(Long authorId) {
        authorRepository.deleteById(authorId);
    }
}
