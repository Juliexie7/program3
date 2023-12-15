package JAC.FSD09.library.mapper;

import JAC.FSD09.library.domain.Author;
import JAC.FSD09.library.dto.AuthorDTO;
import JAC.FSD09.library.entity.AuthorEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class AuthorMapperHelper {

    private final ObjectMapper mapper;

    @Autowired
    public AuthorMapperHelper(ObjectMapper mapper) {
        this.mapper = mapper;
    }


    public List<AuthorDTO> convertAuthorListToAuthorDTOList(List<Author> authors){
        List<AuthorDTO> authorDTOs = new ArrayList<>();
        for(Author temp: authors){
            authorDTOs.add(mapper.convertValue(temp, AuthorDTO.class));
        }

        return authorDTOs;
    }

    public List<Author> convertAuthorEntityListToAuthorList(List<AuthorEntity> authorEntities) {
        List<Author> authorList = new ArrayList<>();
        for (AuthorEntity temp: authorEntities){
            authorList.add(mapper.convertValue(temp, Author.class));
        }
        return authorList;
    }

    public Author convertAuthorEntityToAuthor(AuthorEntity authorEntity) {
        return mapper.convertValue(authorEntity, Author.class);
    }

    public AuthorEntity convertAuthorToAuthorEntity(Author author){
        return mapper.convertValue(author, AuthorEntity.class);
    }

    public Author convertAuthorDTOToAuthor(AuthorDTO authorDTO) {
        return mapper.convertValue(authorDTO, Author.class);
    }

}
