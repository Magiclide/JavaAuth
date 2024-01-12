package developersProject.securityProject.models;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenInfo {
	  private Long userId;
      private LocalDateTime creationTime;
}
