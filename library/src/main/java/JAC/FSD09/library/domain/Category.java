package JAC.FSD09.library.domain;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class Category {

    private Long category_id;

    @NotEmpty
    @NotBlank
    private String categoryName;
    private String description;
    private String ageRange;

}
