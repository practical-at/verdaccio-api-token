# verdaccio-api-token

[![npm version](https://img.shields.io/npm/v/@practical/verdaccio-api-token.svg)](https://www.npmjs.com/package/@practical/verdaccio-api-token)

Minimal Verdaccio Auth Plugin that validates `_authToken` against an external API endpoint.

## Features

- ✅ Only 2 config options: `endpoint`, `timeout`
- ✅ Native `fetch()` (Node.js 18+)
- ✅ Timeout & Error Handling
- ✅ JWT/Token-only Auth
- ✅ Groups support from API response

## Installation

```bash
npm i -g @practical/verdaccio-api-token
```

EXAMPLE

```yaml
auth:
  '@practical/verdaccio-api-token':
    endpoint: https://your-api.com/verdaccio/verify  # Required
    timeout: 5000  # Optional (ms)

# set your auth config as u like
packages:
  'yourPrivatePackage':
    access: $authenticated
    publish: admin 
    unpublish: admin
```
server response should return group which is allowed 
```
// ✅ Success
{ "groups": ["$authenticated"] }

// ❌ Fails
{ "groups": [] }
```



