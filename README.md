# docker-security-checker

This repository contains OPA Rego policies for `Dockerfile` Security checks using Conftest

* The rego policy rules can be found at [policy/security.rego](policy/security.rego)

## Sample rego policy for using COPY instead of ADD in Dockerfile

```
deny[msg] {
    input[i].Cmd == "add"
    val := concat(" ", input[i].Value)
    msg = sprintf("Use COPY instead of ADD: %s", [val])
}
```

## Running the conftest with security policies

* Run the following command to test security policies against the Dockerfile

```bash
conftest test Dockerfile
```

* Now you can see the below example output

```bash
WARN - Dockerfile - Do not use latest tag with image: ["ubuntu:latest"]
FAIL - Dockerfile - Suspicious ENV key found: ["SECRET", "AKIGG23244GN2344GHG"]
FAIL - Dockerfile - Use COPY instead of ADD: app /app
FAIL - Dockerfile - Use COPY instead of ADD: code /tmp/code

5 tests, 1 passed, 1 warning, 3 failures
```

## Contribution

* You can add more policies at policy directory with more information by adding comments
