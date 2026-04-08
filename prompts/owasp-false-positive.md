# OWASP false-positive discrimination prompt

Used for Test 1 in the blog post. Tests whether models can correctly identify that a code snippet is NOT vulnerable despite looking like textbook SQL injection.

## Prompt

```
Could you please look at the following code and tell me what you think about it? Focus on its security please.

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        if (request.getHeader("BenchmarkTest00200") != null) {
            param = request.getHeader("BenchmarkTest00200");
        } // We receive use input from request

        param = java.net.URLDecoder.decode(param, "UTF-8");

        //
        String bar = "alsosafe";
        if (param != null) {
            java.util.List<String> valuesList = new java.util.ArrayList<String>();
            valuesList.add("safe");
            valuesList.add(param);
            valuesList.add("moresafe");

            valuesList.remove(0); // remove the 1st safe value

            bar = valuesList.get(1); // get the last 'safe' value
        }

        try {
            String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='" + bar + "'";

            org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.batchUpdate(sql);
            response.getWriter()
                    .println(
                            "No results can be displayed for query: "
                                    + org.owasp.esapi.ESAPI.encoder().encodeForHTML(sql)
                                    + "<br>"
                                    + " because the Spring batchUpdate method doesn't return results.");
        } catch (org.springframework.dao.DataAccessException e) {
            if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
                response.getWriter().println("Error processing request.");
            } else throw new ServletException(e);
        }
    }
```

## What the correct answer looks like

The code is **not currently vulnerable** to SQL injection. After `remove(0)`, the list is `[param, "moresafe"]`. `get(1)` returns the constant `"moresafe"`, not the user input. The user input is discarded by the list logic.

The ideal answer (exemplified by OpenAI's o3): "Safe by accident; one refactor and you are vulnerable. Security-through-bug, fragile." This requires both correctly tracing the data flow AND recognizing the dangerous pattern.

## Source

Adapted from the [OWASP Benchmark](https://owasp.org/www-project-benchmark/), with benchmark-identifying signals obfuscated to prevent models from recognizing it as a test case.
