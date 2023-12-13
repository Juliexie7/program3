package JAC.FSD09.library.controller;

import JAC.FSD09.library.domain.Author;
import JAC.FSD09.library.dto.AuthorDTO;
import JAC.FSD09.library.mapper.AuthorMapperHelper;
import JAC.FSD09.library.service.AuthorService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.util.List;

import static org.hamcrest.Matchers.hasProperty;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(SpringExtension.class)
@WebMvcTest(controllers = AuthorController.class )
class AuthorControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthorService service;

    @MockBean
    private AuthorMapperHelper mapperHelper;

    private final Author author1 = Author.builder().author_id(1L).authorName("John").nationality("USA").gender("Male").yearBirth("1907").build();
    private final Author author2 = Author.builder().author_id(2L).authorName("Jack").nationality("British").gender("Male").yearBirth("1832").build();
    private final List<Author> authors = List.of(author1, author2);

    private final AuthorDTO authorDTO1 = AuthorDTO.builder().author_id(1L).authorName("John").nationality("USA").gender("Male").yearBirth("1907").build();
    private final AuthorDTO authorDTO2 = AuthorDTO.builder().author_id(2L).authorName("Jack").nationality("British").gender("Male").yearBirth("1832").build();
    private final List<AuthorDTO> authorDTOs = List.of(authorDTO1, authorDTO2);

    @Test
    void test_whenCallListAuthor_return200_withData() throws Exception {

        Mockito.when(service.getAllAuthors()).thenReturn(authors);
        Mockito.when(mapperHelper.convertAuthorListToAuthorDTOList(authors)).thenReturn(authorDTOs);

        mockMvc.perform(MockMvcRequestBuilders.get("/author/list").with(SecurityMockMvcRequestPostProcessors.user("Kate").roles("EMPLOYEE")))
                .andExpect(status().isOk())
                .andExpect(view().name("list_author"))
                .andExpect(model().attribute("authors", authorDTOs))
                .andDo(print());
    }

    @Test
    void test_whenCallShowFormForAdd_return200() throws Exception {

        mockMvc.perform(MockMvcRequestBuilders.get("/author/showFormForAdd").with(SecurityMockMvcRequestPostProcessors.user("Kate").roles("EMPLOYEE")))
                .andExpect(status().isOk())
                .andExpect(view().name("author_form"))
                .andExpect(model().attribute("title", "Add an Author"))
                .andExpect(model().attribute("author", hasProperty("authorName")))
                .andDo(print());
    }
}
