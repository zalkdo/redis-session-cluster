# SpringSessionCluster - Redis
## Redis
- [개발자를 위한 레디스 튜토리얼1](https://meetup.toast.com/posts/224)
- [개발자를 위한 레디스 튜토리얼2](https://meetup.toast.com/posts/225)
- [개발자를 위한 레디스 튜토리얼3](https://meetup.toast.com/posts/226)
- [개발자를 위한 레디스 튜토리얼4](https://meetup.toast.com/posts/227)
### Redis서버 실행
    $ docker run -p 6379:6379 --name cluster-redis -d redis
    # 내부 ip 확인
    $ docker describe <<container id>>
### Redis CLI 실행 및 session 정보확인
    $ docker run -it --network bridge --rm redis redis-cli -h <<continer ip>>
    xxx.xxx.x.x:6379> key *
    # session key 확인
    xxx.xxx.x.x:6379> hgetall spring:session:sessions:<<session id>>
## SpringSession
공식site : https://docs.spring.io/spring-security/site/docs/5.4.1/reference/html5/#session-mgmt

SpringSession의 기본 주요기능들(공식Site참조)
>1. Detecting Timeouts
>2. Concurrent Session Control
>3. Session Fixation Attack Protection
>4. SessionAutehenticationsStrategy
### SpringBoot-Redis initializr
    implementation 'org.springframework.boot:spring-boot-starter-data-redis'
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.session:spring-session-data-redis'
    implementation 'org.springframework.boot:spring-boot-starter-security'
### @EnableRedisHttpSession
세션을 Reids로 관리하는 허용하는 어노테이션이며 AbstractHttpSessionApplicationInitializer상속 받아 구현.

    @Configurable
    @EnableRedisHttpSession(maxInactiveIntervalInSeconds = 60)
    public class RedisHttpSessionConfiguartion extends AbstractHttpSessionApplicationInitializer {
        public RedisHttpSessionConfiguartion(){
             super(RedisHttpSessionConfiguartion.class);
         }
         ...
> **Tip**: Redis CLI 실행 및 session 정보확인 참조. 세션만료키는 30분+5분으로 설졍됨. 이유는 세션삭제되는 찰나에 접근하여 사용하는 경우를 대비한다고 나와있음.

## SpringSecurty
공식Site : https://docs.spring.io/spring-security/site/docs/5.4.1/reference/html5/#servlet-authentication-unpwd
### SpringSecurityConfiguation
@EnableWebSecurity 애너테이션은 웹 보안을 활성화 하며, WebSecurityConfigurer를 구현하거나 WebSecurityConfigurerAdapter를 확장해서 설정
아래 세가지 configure() 메소드를 오버라이딩하고 동작을 설정하는 것으로 웹 보안을 설정.    
 - configure(WebSecurity) : 스프링 시큐리티의 필터 연결을 설정하기 위한 오버라이딩이다
 - configure(HttpSecurity) : 인터셉터로 요청을 안전하게 보호하는 방법을 설정하기 위한 오버라이딩이다
 - configure(AuthenticationManagerBuilder) : 사용자 세부 서비스를 설정하기 위한 오버라이딩이다(Login사용자)
```
    @Configuration
    @EnableWebSecurity
    @RequiredArgsConstructor
    public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
        ...
            @Override
            protected void configure(AuthenticationManagerBuilder auth) throws Exception {
                auth.inMemoryAuthentication()
                        .withUser("user").password(passwordEncoder.encode("1")).roles("USER")
                        .and()
                        .withUser("admin").password(passwordEncoder.encode("2")).roles("ADMIN");
            }
            @Override
            protected void configure(HttpSecurity http) throws Exception {
                http.csrf().disable()
                        .authorizeRequests()
                        .antMatchers("/admin/**").hasRole("ADMIN")
                        .antMatchers("/anonymous*").anonymous()
                        .anyRequest().authenticated();
        
                http.formLogin()
                        .defaultSuccessUrl("/", true)
                        .and()
                        .logout()
                        .logoutUrl("/logout");
            }
```
> **Tip**: auth.inMemoryAuthentication()는 테스트 용도로만 사용됨.
> Spring Security에서 사용가능한 메소드는 [혀노블로그](https://m.blog.naver.com/kimnx9006/220638156019) 참조
#### AuthenticationManagerBuilder
인증을 위한 여러가지 방법은 [혀노블로그](https://m.blog.naver.com/kimnx9006/220634017538)를 참조.
DataSource로 인증 예시
```
        ...
            @Override
            protected void configure(AuthenticationManagerBuilder auth) throws Exception {
                auth.jdbcAuthentication()
                    .dataSource(dataSource)
                    .usersByUsernameQuery("select username, password, true from esauser u where username=?")
                    .authoritiesByUsernameQuery("select username, 'ROLE_USER' from esarole where username=?")
                    .passwordEncoder(new StandardPasswordEncoder("53cr3t"));
            }
        ...
```
사용자 정의 서비스 설정 - UserDetailsServce인터페이스를 구현하고 아래와 같이 설정.
```
        ...
            @Override
            protected void configure(AuthenticationManagerBuilder auth) throws Exception {
                auth.userDetailsService(new UserService(userRepository));
            }
        ...
```
### Form Login
SecurityFilterChain Diagram.
![](https://docs.spring.io/spring-security/site/docs/5.4.1/reference/html5/images/servlet/authentication/unpwd/loginurlauthenticationentrypoint.png)
>1. 권한없는 /privat에 대해 인증되지 않은 요청
>2. FilterEscurityInterceptor는 AccessDeniedException을 발생시켜 미인증 요청에 대해 거부를 표시
>3. 사용자가 미인증이기 때문에, ExeceptionTranslationFilter는 인증을 시작하고 AuthenticationEntryPoint에 설정된 로그인페이지로 리다이렉션.
>4. 브라우져는 리다이렉션된 로그인 페이지를 요청
>5. 애플리케이션 내에서 로그인 페이지를 렌더링

UsernamePasswordAuthenticationFilter는 유져이름과 암로를 인증합니다.
![](https://docs.spring.io/spring-security/site/docs/5.4.1/reference/html5/images/servlet/authentication/unpwd/usernamepasswordauthenticationfilter.png)
>1. HttpServletRequest에서 유저이름과 암호를 추출하여 인증하여 UsernamePasswordAuthenticationToken을 생성
>2. Token이 AuthenticationManager에 전달되어 인증.(사용자 저장방식에 따라 다름)
>3. 인증 실패
>>* SecurityContextHolder clear
>>* RememberMeServices.loginFail 호출
>>* AuthenticationFailureHandler 호출
>4. 인증 성공
>>* SessioniAuthenticationStrategy에 새로운 로그인 통보
>>* SecutiryContextHolder에 인증 설정   
>>* RememberMeServices.loginSuccess 호출
>>* ApplicationEventPublisher가 InteractiveAuthenticationSuccessEvent 게시
>>* AuthenticationSuccessHandler 호출됨. 일반적으로 로그인페이지로 리디렉션 시에 ExeceptionTranslationFilter에 의해 저장된 요청으로 리디렉션되는 SimpleUrlAuthenticationSuccessHandler임

###JDBC Authentication
Embedded DB H2 사용, users/authorities table이 자동생성.
```
    @Bean
    DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
            .setType(H2)
            .addScript("classpath:org/springframework/security/core/userdetails/jdbc/users.ddl")
            .build();
    }
```
application.yml과 build.gradle에 추가
```
    spring:
      h2:
        console:
          enabled: true
      datasource:
        driver-class-name: org.h2.Driver
        url: jdbc:h2:mem:testdb
        username: sa
        password:
```
```
    implementation 'org.springframework.boot:spring-boot-starter-jdbc'
    implementation 'com.h2database:h2'
```
> **Tip**: H2 console 접근 시 고려사항 - [cncf/frameOptions설정](https://springframework.guru/using-the-h2-database-console-in-spring-boot-with-spring-security/)

JdbcUserDetailsManager Example
```
@Bean
UserDetailsManager users(DataSource dataSource) {
    UserDetails user = User.builder()
        .username("user")
        .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
        .roles("USER")
        .build();
    UserDetails admin = User.builder()
        .username("admin")
        .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
        .roles("USER", "ADMIN")
        .build();
    JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
    users.createUser(user);
    users.createUser(admin);
}
```
### DaoAuthenticationProvider
![](https://docs.spring.io/spring-security/site/docs/5.4.1/reference/html5/images/servlet/authentication/unpwd/daoauthenticationprovider.png)
>1. 유저이름과 암화 인증 필터는 UsernamePasswordAuthenticationToken을 AuthenticationManager로 전달
>2. ProviderManager는 DaoAuthenticationProvider유형의 AuthenticationProvider를 사용하도록 구성
>3. DaoAuthenticationProvider는 UserDetailServe에서 UserDetails를 찾음
>4. DaoAuthenticationProvider는 PasswordEncoder를 사용해서 UserDetails의 password를 검증
>5. 인증을 성공하면 Token은 UserDetail를 가지고, 궁극적으로 Token은 인증 필터에 의해 SecurityContextHolder에 설정

###Remember-Me Authentication
