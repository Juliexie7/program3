package JAC.FSD09.library.mapper;

import JAC.FSD09.library.domain.Author;
import JAC.FSD09.library.dto.AuthorDTO;
import JAC.FSD09.library.entity.AuthorEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class AuthorMapperHelperTest {

    @InjectMocks
    private AuthorMapperHelper underTest;

    @Mock
    private ObjectMapper objectMapper;

    private final AuthorEntity authorEntity1 = AuthorEntity.builder().author_id(1L).authorName("John").nationality("USA").gender("Male").yearBirth("1907").build();
    private final AuthorEntity authorEntity2 = AuthorEntity.builder().author_id(2L).authorName("Jack").nationality("British").gender("Male").yearBirth("1832").build();
    private final List<AuthorEntity> authorEntityList =List.of(authorEntity1, authorEntity2);
    private final Author author1 = Author.builder().author_id(1L).authorName("John").nationality("USA").gender("Male").yearBirth("1907").build();
    private final Author author2 = Author.builder().author_id(2L).authorName("Jack").nationality("British").gender("Male").yearBirth("1832").build();
    private final List<Author> authors = List.of(author1, author2);

    private final AuthorDTO authorDTO1 = AuthorDTO.builder().author_id(1L).authorName("John").nationality("USA").gender("Male").yearBirth("1907").build();
    private final AuthorDTO authorDTO2 = AuthorDTO.builder().author_id(2L).authorName("Jack").nationality("British").gender("Male").yearBirth("1832").build();
    private final List<AuthorDTO> authorDTOs = List.of(authorDTO1, authorDTO2);

    @Test
    void test_convertAuthorListToAuthorDTOList_returnAuthorDTOList(){

        Mockito.when(objectMapper.convertValue(author1, AuthorDTO.class)).thenReturn(authorDTO1);
        Mockito.when(objectMapper.convertValue(author2, AuthorDTO.class)).thenReturn(authorDTO2);

        var expected = List.of(authorDTO1, authorDTO2);

        var actual = underTest.convertAuthorListToAuthorDTOList(authors);

        assertEquals(expected, actual);
        verify(objectMapper, times(2)).convertValue(any(Author.class), eq(AuthorDTO.class));
    }

    @Test
    void test_convertAuthorEntityListToAuthorList_returnAuthorList(){

        Mockito.when(objectMapper.convertValue(authorEntity1, Author.class)).thenReturn(author1);
        Mockito.when(objectMapper.convertValue(authorEntity2, Author.class)).thenReturn(author2);

        var expected = List.of(author1, author2);

        var actual = underTest.convertAuthorEntityListToAuthorList(authorEntityList);

        assertEquals(expected, actual);
        verify(objectMapper, times(2)).convertValue(any(AuthorEntity.class), eq(Author.class));
    }

    @Test
    void test_convertAuthorEntityToAuthor_returnAuthor(){
        Mockito.when(objectMapper.convertValue(authorEntity1, Author.class)).thenReturn(author1);

        var actual = underTest.convertAuthorEntityToAuthor(authorEntity1);

        assertEquals(author1, actual);
    }

    @Test
    void test_convertAuthorToAuthorEntity_returnAuthorEntity(){
        Mockito.when(objectMapper.convertValue(author1, AuthorEntity.class)).thenReturn(authorEntity1);

        var actual = underTest.convertAuthorToAuthorEntity(author1);

        assertEquals(authorEntity1, actual);
    }

    @Test
    void test_convertAuthorDTOToAuthor_returnAuthor(){
        Mockito.when(objectMapper.convertValue(authorDTO1, Author.class)).thenReturn(author1);

        var actual = underTest.convertAuthorDTOToAuthor(authorDTO1);

        assertEquals(author1, actual);
    }
}
