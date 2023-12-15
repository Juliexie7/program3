package JAC.FSD09.library.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class AuthorDTO {

    private Long author_id;

    @NotEmpty
    @NotBlank
    private String authorName;
    private String nationality;
    private String gender;
    private String yearBirth;

}
