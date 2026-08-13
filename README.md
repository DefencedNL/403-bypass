# bypass_403.sh

Test veelvoorkomende HTTP 403-bypass technieken (headers, methoden, path-manipulatie)

## Vereist

`bash` en `curl`

## Gebruik

```bash
bash bypass_403.sh [opties] <URL>
```

## Opties

| Optie | Kort | Beschrijving |
|-------|------|--------------|
| `--cookies` | `-c` | Cookie-header in Burp-notatie: `"naam=waarde; naam2=waarde2"` |
| `--header`  | `-H` | Extra header zoals bij curl. Mag meerdere keren. |
| `--help`    | `-h` | Toon hulptekst. |

## Voorbeelden

Anoniem:

```bash
bash bypass_403.sh https://target.tld/admin
```

Geauthenticeerd met cookies:

```bash
bash bypass_403.sh -c "csrftoken=zH8p2...; session=3a1lp..." https://target.tld/admin
```

Met bearer-token en extra header:

```bash
bash bypass_403.sh \
  -H "Authorization: Bearer eyJ..." \
  -H "X-Api-Key: abc123" \
  https://target.tld/admin
```

## Output lezen

- **Groen (2xx)** = mogelijke bypass.
- **Rood (401/403)** = geen bypass 
