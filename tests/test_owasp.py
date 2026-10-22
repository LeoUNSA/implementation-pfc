from vulnpipe.corpus.owasp import neutralise, read_expected
from vulnpipe.corpus.sanitize import strip_comments
from vulnpipe.sast.materialize import wrap_snippet
from vulnpipe.schemas import Snippet

SRC = '''/** OWASP Benchmark header */
package org.owasp.benchmark.testcode;
import java.io.IOException;
@WebServlet(value = "/sqli-01/BenchmarkTest00042")
public class BenchmarkTest00042 extends HttpServlet {
    // condition 'B', which is safe
    String url = "http://x"; /* trailing */
    String bar = "alsosafe";
    String p = request.getHeader("BenchmarkTest00042");
}
'''


def test_strip_comments_keeps_slashes_inside_strings():
    out = strip_comments(SRC)
    assert "which is safe" not in out and "header" not in out
    assert '"http://x"' in out


def test_neutralise_removes_label_and_category_hints():
    out = neutralise(SRC)
    for hint in ("safe", "sqli", "BenchmarkTest"):
        assert hint not in out
    assert "public class TestCase" in out
    assert 'getHeader("TestCase")' in out


def test_read_expected_filters_and_labels(tmp_path):
    csv = tmp_path / "expected.csv"
    csv.write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,pathtraver,true,22\n"
        "BenchmarkTest00002,xss,true,79\n"
        "BenchmarkTest00003,sqli,false,89\n"
    )
    assert read_expected(csv) == [
        ("BenchmarkTest00001", "22", 1),
        ("BenchmarkTest00003", "89", 0),
    ]


def test_whole_file_snippet_is_materialised_verbatim():
    code = neutralise(SRC)
    s = Snippet(snippet_id="owasp_CWE89__x", cwe="89", label=1, code=code, file="x.java")
    assert wrap_snippet(s).strip() == code.strip()
