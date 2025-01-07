package com.fm6mhz.auth


import org.springframework.http.MediaType
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post

// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

interface WebMvcTestBase {

    default MockHttpServletRequestBuilder httpGet(String path) {
        return get(URI.create(path))
    }

    default MockHttpServletRequestBuilder httpPost(String path) {
        return post(URI.create(path))
                .contentType(MediaType.APPLICATION_JSON)
                .characterEncoding('UTF-8')
                .with(csrf())
    }

    default MockHttpServletRequestBuilder httpDelete(String path) {
        return delete(URI.create(path))
                .with(csrf())
    }
}