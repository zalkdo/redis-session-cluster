package study.zalkdo.redissessioncluster;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

/*
@RestController
@EnableRedisHttpSession
 */
@SpringBootApplication
public class RedisSessionClusterApplication {

    public static void main(String[] args) {
        SpringApplication.run(RedisSessionClusterApplication.class, args);
    }
/*
    @GetMapping("/")
    public String index(HttpSession session){
        session.setAttribute("name","zalkdo");
        return session.getId() + "\nHello "+session.getAttribute("name");
    }
*/
}
