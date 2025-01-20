package org.example;

import org.junit.jupiter.api.Test;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.PolicyException;
import org.owasp.validator.html.ScanException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AntisamyTest {

    @Test
    void testAntisamy() throws PolicyException, ScanException {
        //Given
        AntiSamy antiSamy = new AntiSamy();
        String taintedHtml = "<html><body><style>.cl { color: rgb(0%,0%,0%); }</style></body></html>";
        Policy policy = Policy.getInstance();

        //When
        CleanResults results = antiSamy.scan(taintedHtml, policy);

        //Then
        assertEquals(0, results.getNumberOfErrors());
        assertNotNull(results.getCleanHTML());
    }
}
