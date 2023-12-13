package JAC.FSD09.library.dto;

import JAC.FSD09.library.domain.Author;
import JAC.FSD09.library.domain.Category;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class BookDTO {

    private Long book_id;

    @NotEmpty
    @NotBlank
    private String title;
    private String ISBN;
    private String edition;
    private String description;
    private int amountInLibrary;

    @NotNull
    private AuthorDTO author;
    @NotNull
    private CategoryDTO category;
}
