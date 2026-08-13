# bypass_403.sh

Tests common HTTP 403 bypass techniques (headers, methods, path manipulation) against a single URL.

## Requirements

- `bash` and `curl`

## Usage

```bash
bash bypass_403.sh [options] <URL>
```

## Options

| Option | Short | Description |
|--------|-------|-------------|
| `--cookies` | `-c` | Cookie header in Burp notation: `"name=value; name2=value2"` |
| `--header`  | `-H` | Extra header like curl. May be repeated. |
| `--help`    | `-h` | Show help text. |

## Examples

Anonymous:

```bash
bash bypass_403.sh https://target.tld/admin
```

Authenticated with cookies:

```bash
bash bypass_403.sh -c "csrftoken=zH8p2...; session=3a1lp..." https://target.tld/admin
```

With a bearer token and an extra header:

```bash
bash bypass_403.sh \
  -H "Authorization: Bearer eyJ..." \
  -H "X-Api-Key: abc123" \
  https://target.tld/admin
```

## Reading the output

- **Green (2xx)** = possible bypass.
- **Red (401/403)** = still blocked.
