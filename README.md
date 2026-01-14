# verdaccio-api-token

[![npm version](https://img.shields.io/npm/v/@practical/verdaccio-api-token.svg)](https://www.npmjs.com/package/@practical/verdaccio-api-token)

Minimal Verdaccio Auth Plugin that validates non JWT `_authToken` against an external API endpoint.
Can be used with Verdaccios alongside with npm login & JWT for web UI.

## Features

- ✅ Only 2 config options: `endpoint`, `timeout`
- ✅ Native `fetch()` (Node.js 18+)
- ✅ Timeout & Error Handling
- ✅ **htpasswd Compatible**: Enables simultaneous `npm login` with username/password
- ✅ **JWT Support**: Web UI login works unchanged
- ✅ Allowed groups dynamically from API response

## Setup

```bash
# Install the plugin either globally or in your plugins folder
npm i @practical/verdaccio-api-token

```

## config.yaml
```yaml


# verdaccio will look for the plugin globally in your node_modules folder
# for local installation you can specify the plugins folder
plugins: ./plugins/node_modules # optional


# !!! Important: Place the plugin before htpasswd so custom tokens are checked first
auth:
  '@practical/verdaccio-api-token':
    endpoint: https://your-api.com/verdaccio/verify  # Required
    timeout: 5000  # Optional (ms)
  htpasswd:
    file: ./htpasswd
    max_users: -1

# set your auth config as u like
packages:
  'yourPrivatePackage':
    access: $authenticated
    publish: admin developer #example users create your own
    unpublish: admin
```

in the projects' `.npmrc` file add the token 

``
//registry.your-domain.com/:_authToken=YOUR_API_TOKEN
``

API Endpoint Format
Your validation endpoint must support this request/response format:

Request:

```json
{
  "token": "your-custom-token-here"
}
```

Response (Valid Token):

```json
{
  "groups": ["developers", "users"]
}
```

API Response should return groups that you defined or an empty array
find out more about package access https://www.verdaccio.org/docs/packages

```
// ✅ Success
{ "groups": ["$authenticated"] }

// ❌ Fails
{ "groups": [] }
```



