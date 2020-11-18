package study.zalkdo.redissessioncluster;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;

@RestController
public class TestController {
/*
    @GetMapping("/")
    public String root(){
        return "redirect:/index";
    }
    @GetMapping("/index")
    public String index(){
        return "index";
    }
*/
    @GetMapping("/user")
    public ModelAndView userIndex(){
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("/user/index");
        return modelAndView;
    }

    @GetMapping("/login")
    public ModelAndView login(){
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("login");
        return modelAndView;
    }

    @GetMapping("/login-error")
    public ModelAndView loginError(){
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.addObject("loginError", true);
        modelAndView.setViewName("login");
        return modelAndView;
    }

}
