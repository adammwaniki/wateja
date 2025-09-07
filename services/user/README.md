# User Service

## How To Test API Using Postman Collection

Copy and import the following json script into your Postman collections and then run.

The variables you'll need to set in your postman environment are at the end of the json script.

```json
{
  "info": {
    "_postman_id": "Wateja User Service API",
    "name": "Wateja User Service API Testing",
    "description": "Enhanced testing collection for user registration, authentication, profile management, and sessions",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Health & Setup",
      "item": [
        {
          "name": "Gateway Health Check",
          "request": {
            "method": "GET",
            "header": [],
            "url": {
              "raw": "{{base_url}}/healthz",
              "host": ["{{base_url}}"],
              "path": ["healthz"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Gateway health check successful', function() {",
                  "    pm.response.to.have.status(204);",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        }
      ]
    },
    {
      "name": "User Registration & Authentication",
      "item": [
        {
          "name": "Register New User",
          "request": {
            "method": "POST",
            "header": [
              { "key": "Content-Type", "value": "application/json" }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"first_name\": \"John\",\n  \"last_name\": \"Doe\",\n  \"email\": \"john.doe@example.com\",\n  \"password\": \"securepassword123\"\n}"
            },
            "url": {
              "raw": "{{base_url}}/users/register",
              "host": ["{{base_url}}"],
              "path": ["users", "register"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Registration successful', function() {",
                  "    pm.response.to.have.status(201);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response).to.have.property('user');",
                  "    pm.expect(response).to.have.property('token_data');",
                  "    pm.expect(response).to.have.property('session_id');",
                  "    ",
                  "    pm.environment.set('access_token', response.token_data.access_token);",
                  "    pm.environment.set('refresh_token', response.token_data.refresh_token);",
                  "    pm.environment.set('session_id', response.session_id);",
                  "    pm.environment.set('user_id', response.user.id);",
                  "    pm.environment.set('user_email', response.user.email);",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "Login with Password",
          "request": {
            "method": "POST",
            "header": [
              { "key": "Content-Type", "value": "application/json" }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"email\": \"{{user_email}}\",\n  \"password\": \"securepassword123\"\n}"
            },
            "url": {
              "raw": "{{base_url}}/auth/login",
              "host": ["{{base_url}}"],
              "path": ["auth", "login"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Login successful', function() {",
                  "    pm.response.to.have.status(200);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response).to.have.property('user');",
                  "    pm.expect(response).to.have.property('token_data');",
                  "    pm.expect(response).to.have.property('session_id');",
                  "    ",
                  "    pm.environment.set('access_token', response.token_data.access_token);",
                  "    pm.environment.set('refresh_token', response.token_data.refresh_token);",
                  "    pm.environment.set('session_id', response.session_id);",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "Refresh Token",
          "request": {
            "method": "POST",
            "header": [
              { "key": "Content-Type", "value": "application/json" }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"refresh_token\": \"{{refresh_token}}\"\n}"
            },
            "url": {
              "raw": "{{base_url}}/auth/refresh",
              "host": ["{{base_url}}"],
              "path": ["auth", "refresh"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Token refreshed successfully', function() {",
                  "    pm.response.to.have.status(200);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response).to.have.property('access_token');",
                  "    pm.expect(response).to.have.property('refresh_token');",
                  "    pm.environment.set('access_token', response.access_token);",
                  "    pm.environment.set('refresh_token', response.refresh_token);",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        }
      ]
    },
    {
      "name": "Protected User Operations",
      "item": [
        {
          "name": "Get User Profile",
          "request": {
            "method": "GET",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" }
            ],
            "url": {
              "raw": "{{base_url}}/auth/profile",
              "host": ["{{base_url}}"],
              "path": ["auth", "profile"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Profile retrieved successfully', function() {",
                  "    pm.response.to.have.status(200);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response).to.have.property('id');",
                  "    pm.expect(response.id).to.equal(pm.environment.get('user_id'));",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "Get User by ID",
          "request": {
            "method": "GET",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" }
            ],
            "url": {
              "raw": "{{base_url}}/users/{{user_id}}",
              "host": ["{{base_url}}"],
              "path": ["users", "{{user_id}}"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('User retrieved successfully', function() {",
                  "    pm.response.to.have.status(200);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response).to.have.property('id');",
                  "    pm.expect(response.id).to.equal(pm.environment.get('user_id'));",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "Update User Profile",
          "request": {
            "method": "PUT",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" },
              { "key": "Content-Type", "value": "application/json" }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"user\": {\n    \"first_name\": \"Jane\",\n    \"last_name\": \"Smith\"\n  },\n  \"update_mask\": [\"first_name\", \"last_name\"]\n}"
            },
            "url": {
              "raw": "{{base_url}}/users/{{user_id}}",
              "host": ["{{base_url}}"],
              "path": ["users", "{{user_id}}"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('User updated successfully', function() {",
                  "    pm.response.to.have.status(200);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response.first_name).to.equal('Jane');",
                  "    pm.expect(response.last_name).to.equal('Smith');",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "List Users",
          "request": {
            "method": "GET",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" }
            ],
            "url": {
              "raw": "{{base_url}}/users?page_size=10",
              "host": ["{{base_url}}"],
              "path": ["users"],
              "query": [
                { "key": "page_size", "value": "10" }
              ]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Users listed successfully', function() {",
                  "    pm.response.to.have.status(200);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response).to.have.property('users');",
                  "    pm.expect(response.users).to.be.an('array');",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "Delete User",
          "request": {
            "method": "DELETE",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" }
            ],
            "url": {
              "raw": "{{base_url}}/users/{{user_id}}",
              "host": ["{{base_url}}"],
              "path": ["users", "{{user_id}}"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('User deletion returns expected response', function() {",
                  "    pm.expect([204, 401]).to.include(pm.response.code);",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        }
      ]
    },
    {
      "name": "Session Management",
      "item": [
        {
          "name": "Get Active Sessions",
          "request": {
            "method": "GET",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" }
            ],
            "url": {
              "raw": "{{base_url}}/auth/sessions",
              "host": ["{{base_url}}"],
              "path": ["auth", "sessions"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Sessions retrieved successfully', function() {",
                  "    pm.response.to.have.status(200);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response).to.have.property('sessions');",
                  "    pm.expect(response).to.have.property('count');",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "Logout Current Session",
          "request": {
            "method": "POST",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" },
              { "key": "Content-Type", "value": "application/json" }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"refresh_token\": \"{{refresh_token}}\"\n}"
            },
            "url": {
              "raw": "{{base_url}}/auth/logout",
              "host": ["{{base_url}}"],
              "path": ["auth", "logout"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Logout successful', function() {",
                  "    pm.response.to.have.status(200);",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "Verify Access After Logout",
          "request": {
            "method": "GET",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" }
            ],
            "url": {
              "raw": "{{base_url}}/auth/profile",
              "host": ["{{base_url}}"],
              "path": ["auth", "profile"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Access denied after logout', function() {",
                  "    pm.response.to.have.status(401);",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        }
      ]
    }
  ],
  "variable": [
    { "key": "base_url", "value": "http://localhost:8080/api/v1" },
    { "key": "access_token", "value": "" },
    { "key": "refresh_token", "value": "" },
    { "key": "session_id", "value": "" },
    { "key": "user_id", "value": "" },
    { "key": "user_email", "value": "" }
  ]
}
```
