/* A minimal Juliet-style test case used only by the corpus unit tests.
 * Mirrors the real Juliet structure: a bad() method (vulnerable) and a
 * goodG2B() method (fixed), so the extractor's labelling can be checked.
 */
package testcases.CWE89_SQL_Injection;

import java.sql.Connection;
import java.sql.Statement;

public class CWE89_SQL_Injection__fixture_01 {

    public void bad(String userInput, Connection conn) throws Exception {
        // FLAW: user input concatenated straight into the query string.
        String query = "select * from users where name = '" + userInput + "'";
        Statement st = conn.createStatement();
        st.executeQuery(query);
    }

    public void goodG2B(String userInput, Connection conn) throws Exception {
        // FIX: hard-coded safe value, no untrusted input reaches the query.
        String query = "select * from users where name = 'admin'";
        Statement st = conn.createStatement();
        st.executeQuery(query);
    }
}
