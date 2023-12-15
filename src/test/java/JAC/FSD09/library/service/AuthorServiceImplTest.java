package JAC.FSD09.library.service;

import JAC.FSD09.library.domain.Author;
import JAC.FSD09.library.entity.AuthorEntity;
import JAC.FSD09.library.exception.IdNotFoundException;
import JAC.FSD09.library.mapper.AuthorMapperHelper;
import JAC.FSD09.library.repository.AuthorRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorServiceImplTest {

    @InjectMocks
    private AuthorServiceImpl underTest;

    @Mock
    private AuthorRepository authorRepository;

    @Mock
    private AuthorMapperHelper authorMapperHelper;

    private final AuthorEntity authorEntity1 = AuthorEntity.builder().author_id(1L).authorName("John").nationality("USA").gender("Male").yearBirth("1907").build();
    private final AuthorEntity authorEntity2 = AuthorEntity.builder().author_id(2L).authorName("Jack").nationality("British").gender("Male").yearBirth("1832").build();
    private final List<AuthorEntity> authorEntityList =List.of(authorEntity1, authorEntity2);
    private final Author author1 = Author.builder().author_id(1L).authorName("John").nationality("USA").gender("Male").yearBirth("1907").build();
    private final Author author2 = Author.builder().author_id(2L).authorName("Jack").nationality("British").gender("Male").yearBirth("1832").build();
    private final List<Author> authors = List.of(author1, author2);

    @Test
    void test_getAllAuthors_returnList(){
        Mockito.when(authorRepository.findAll()).thenReturn(authorEntityList);
        Mockito.when(authorMapperHelper.convertAuthorEntityListToAuthorList(authorEntityList)).thenReturn(authors);

        var actual = underTest.getAllAuthors();

        assertEquals(authors, actual);
    }

    @Test
    void test_getAllAuthors_returnEmptyList(){
        Mockito.when(authorRepository.findAll()).thenReturn(Collections.emptyList());
        Mockito.when(authorMapperHelper.convertAuthorEntityListToAuthorList(Collections.emptyList())).thenReturn(Collections.emptyList());

        var actual = underTest.getAllAuthors();

        assertEquals(0,actual.size());
        assertEquals(Collections.emptyList(), actual);
    }

    @Test
    void test_saveAuthor_returnId(){
        Mockito.when(authorMapperHelper.convertAuthorToAuthorEntity(author1)).thenReturn(authorEntity1) ;
        Mockito.when(authorRepository.save(authorEntity1)).thenReturn(authorEntity1);

        var actual = underTest.saveAuthor(author1);

        assertEquals(authorEntity1.getAuthor_id(), actual);
    }

    @Test
    void test_findAuthorById_returnAuthor() throws IdNotFoundException {
        Mockito.when(authorRepository.findById(1L)).thenReturn(Optional.of(authorEntity1));
        Mockito.when(authorMapperHelper.convertAuthorEntityToAuthor(authorEntity1)).thenReturn(author1);

        var actual = underTest.findAuthorById(1L);

        assertEquals(author1, actual);
        verify(authorMapperHelper, times(1)).convertAuthorEntityToAuthor(any(AuthorEntity.class));
    }

    @Test
    void test_findAuthorById_throwsException() throws IdNotFoundException {
        Long authId = 3L;
        Mockito.when(authorRepository.findById(authId)).thenReturn(Optional.empty());

        assertThrows(IdNotFoundException.class,
                () -> underTest.findAuthorById(3L),
                "There is no author by id " + authId);

        verify(authorMapperHelper, never()).convertAuthorEntityToAuthor(any(AuthorEntity.class));
    }

}
