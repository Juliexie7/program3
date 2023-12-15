package JAC.FSD09.library.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class CategoryDTO {

    private Long category_id;

    @NotEmpty
    private String categoryName;
    private String description;

    @NotEmpty
    private String ageRange;

}
