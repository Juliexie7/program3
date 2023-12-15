package JAC.FSD09.library.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.util.List;

@Entity
@Table(name = "book")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class BookEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long book_id;


    @Column(name="title")
    private String title;

    @Column(name="ISBN")
    private String ISBN;

    @Column(name="edition")
    private String edition;

    @Column(name="description")
    private String description;

    @Column(name="amount_in_library")
    private int amountInLibrary;

    @ManyToOne
    @JoinColumn(name="author_id", nullable=false)
    private AuthorEntity author;

    @ManyToOne
    @JoinColumn(name="category_id", nullable=false)
    private CategoryEntity category;

}
