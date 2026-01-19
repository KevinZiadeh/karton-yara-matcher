# Karton FLOSS
> [Karton](https://github.com/CERT-Polska/karton) service to run [YARA](https://virustotal.github.io/yara/) on samples.

## Prerequisites

This is to be used as part of a [Karton](https://github.com/CERT-Polska/karton) pipeline. It has been setup as a [Docker](https://www.docker.com/) container.

Recommended **docker compose** setup:

```yml
karton-yara-matcher:
  build:
    context: karton/yara_matcher
  tty: true
  develop:
    watch:
      - action: sync+restart
        path: karton/yara_matcher
        target: /app
        ignore:
          - karton/yara_matcher/.venv/
      - action: rebuild
        path: karton/yara_matcher/uv.lock
      - action: rebuild
        path: karton/yara_matcher/Dockerfile
  depends_on:
    - karton-system
    - mwdb-web
  volumes:
    - karton/yara_matcher/rules/custom:/app/rules/custom # Custom YARA rules
    - ./karton.docker.ini:/etc/karton/karton.ini
```

## Behavior

For a given sample, run **YARA** on it and add **tags** of the form `yara:<RULE_NAME>`.

**Consumes:**
```json
{"type": "sample", "stage": "recognized"}
```

**Produces:**
```json
{
  "headers": {"type": "sample", "stage": "analyzed"},
  "payload": {
    "sample": sample,
    "tags": <YARA tags>,
  }
}
```

By default, this will include the rules by [ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules/). **Custom** rules can be included using the [`rules/custom`](./rules/custom) directory.