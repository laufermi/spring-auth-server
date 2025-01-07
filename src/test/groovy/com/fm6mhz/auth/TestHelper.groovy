package com.fm6mhz.auth

import feign.Request
import feign.RequestTemplate

import java.nio.charset.Charset
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter

class TestHelper {

    static DateTimeFormatter formatter = DateTimeFormatter.ofPattern('yyyy-MM-dd HH:mm:ss')

    static Request FAKE_FEIGN_REQUEST = Request.create(Request.HttpMethod.GET, 'http://fake-domain.com', [:], null, Charset.defaultCharset(), new RequestTemplate())

    static Instant parseStringToInstant(String dateAsString) {
        return LocalDateTime.parse(dateAsString, formatter)
                .atZone(ZoneId.systemDefault())
                .toInstant()
    }

}