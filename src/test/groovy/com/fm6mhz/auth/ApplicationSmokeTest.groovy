package com.fm6mhz.auth

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContext
import org.springframework.test.context.ActiveProfiles
import spock.lang.Specification

@SpringBootTest
@ActiveProfiles('test')
class ApplicationSmokeTest extends Specification {

    @Autowired
    ApplicationContext applicationContext

    def 'We can get bean from context'() {
        expect:
            applicationContext.getBean('application') != null
    }

    def 'We can get active profiles from context'() {
        expect:
            applicationContext.environment.activeProfiles == ['test'] as String[]
    }
}
