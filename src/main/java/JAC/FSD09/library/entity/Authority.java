package JAC.FSD09.library.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "authorities")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class Authority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "username")
    private String userName;

    @Column(name = "authority")
    private String authority;

    @ManyToOne
    @JoinColumn(name="user_id", nullable=false)
    private User user;

}
