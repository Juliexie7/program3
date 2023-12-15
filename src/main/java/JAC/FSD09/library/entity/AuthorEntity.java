package JAC.FSD09.library.entity;

import JAC.FSD09.library.domain.Book;
import jakarta.persistence.*;
import lombok.*;

import java.util.List;

@Entity
@Table(name = "author")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class AuthorEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long author_id;

    @Column(name="author_name")
    private String authorName;

    @Column(name="nationality")
    private String nationality;

    @Column(name="gender")
    private String gender;

    @Column(name="birth_year")
    private String yearBirth;

//    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy="author")
//    private List<BookEntity> books;
}
