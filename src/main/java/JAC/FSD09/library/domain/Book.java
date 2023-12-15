package JAC.FSD09.library.domain;

import jakarta.validation.constraints.*;
import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class Book {

    private Long book_id;

    @NotBlank
    @NotEmpty
    private String title;
    private String ISBN;
    private String edition;
    private String description;

    @NotBlank
    @Digits(integer = 3 , fraction = 0)
    @DecimalMin("0")
    private int amountInLibrary;
    @NotNull
    private Author author;
    @NotNull
    private Category category;

}
