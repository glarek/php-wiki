# API Documentation v1.0

This guide is intended for developers building frontend applications (e.g., SvelteKit) consuming the PHP Wiki API.

## Base URL

Production: `https://api.tryckfall.nu/api`
Local: `http://localhost:8000/api`

## Authentication Flow

### 1. Register User

- **Endpoint**: `POST /auth/register`
- **Body**:
  ```json
  {
    "password": "securePassword123",
    "email": "john@example.com",
    "first_name": "John",
    "last_name": "Doe"
  }
  ```
- **Response (201 Created)**:
  ```json
  { "status": "success", "message": "Registration successful..." }
  ```
- **Validation**: Returns `400 Bad Request` if email is invalid or `409 Conflict` if user exists.

### 2. Verify Email

User clicks a link sent to their email.

- **Endpoint**: `GET /auth/verify?token=YOUR_HEX_TOKEN`
- **Response (200 OK)**:
  ```json
  { "status": "success", "message": "Account verified..." }
  ```

### 3. Login

- **Endpoint**: `POST /auth/login`
- **Body**:
  ```json
  { "email": "john@example.com", "password": "securePassword123" }
  ```
- **Response (200 OK)**:
  ```json
  {
    "status": "success",
    "token": "eyJhbGciOiJIUzI1Ni...", // Access Token (valid 1 hour)
    "refresh_token": "a1b2c3d4...", // Refresh Token (valid 7 days)
    "user": {
      "first_name": "John",
      "last_name": "Doe",
      "email": "john@example.com",
      "role": "guest"
    }
  }
  ```
- **Note**: Returns `403` if account is not verified.

### 4. Refresh Token

Used to obtain a new Access Token when the current one expires.

- **Endpoint**: `POST /auth/refresh`
- **Body**:
  ```json
  { "refresh_token": "YOUR_REFRESH_TOKEN" }
  ```
- **Response (200 OK)**:
  ```json
  {
    "status": "success",
    "token": "eyJhbGciOiJIUzI1Ni...", // New Access Token
    "refresh_token": "new_random_token..." // New Refresh Token (Rolled)
  }
  ```
- **Error**: Returns `401` if refresh token is invalid/expired.

### 5. Forgot Password

Initiates the password reset process. Sending duplicate requests is safe (always returns success).

- **Endpoint**: `POST /auth/forgot-password`
- **Body**:
  ```json
  { "email": "john@example.com" }
  ```
- **Response (200 OK)**:
  ```json
  { "status": "success", "message": "If the email exists..." }
  ```

### 6. Reset Password

Completes the password reset process using the token sent via email.

- **Endpoint**: `POST /auth/reset-password`
- **Body**:
  ```json
  {
    "token": "TOKEN_FROM_EMAIL_LINK",
    "password": "newSecurePassword123"
  }
  ```
- **Response (200 OK)**:
  ```json
  { "status": "success", "message": "Password has been reset..." }
  ```

## Public Data (Wiki)

### Get Navigation Menu

Returns a hierarchical list of categories to build the sidebar.

- **Endpoint**: `GET /wiki/menu`
- **Response**:
  ```json
  {
    "status": "success",
    "data": [
      {
        "id": 1,
        "name": "Introduction",
        "slug": "intro",
        "articles": [
          { "id": 10, "title": "Getting Started", "slug": "getting-started" }
        ]
      }
    ]
  }
  ```

### Get Article Content

- **Endpoint**: `GET /wiki/article/{slug}`
- **Response**:
  ```json
  {
    "status": "success",
    "data": {
      "id": 10,
      "title": "Getting Started",
      "content": "<h1>Hello World</h1>...",
      "author_id": 1,
      "category_id": 1,
      "created_at": "2024-01-01 12:00:00"
    }
  }
  ```

## Admin API

**Requirement**: Add header `Authorization: Bearer <YOUR_JWT_TOKEN>` to all requests below. User must have `role: admin`.

### Categories

- `POST /wiki/categories`: `{ name, slug, sort_order }`
- `PUT /wiki/categories/{id}`: `{ name, slug, sort_order }`
- `DELETE /wiki/categories/{id}`

### Articles

- `POST /wiki/articles`: `{ category_id, title, slug, content }`
- `PUT /wiki/articles/{id}`: `{ category_id, title, slug, content }`
- `DELETE /wiki/articles/{id}`

### Image Upload

used to embed images in articles.

- **Endpoint**: `POST /wiki/upload`
- **Body**: Multipart Form Data -> Key `image` (File)
- **Response**:
  ```json
  {
    "status": "success",
    "url": "https://api.tryckfall.nu/uploads/a1b2c3d4.png",
    "filename": "a1b2c3d4.png"
  }
  ```

## Error Handling

All errors follow this JSON format:

```json
{
  "status": "error",
  "code": "ERROR_CODE_STRING", // Specific error code
  "message": "Human readable error description"
}
```

### Standard Response Codes

| Code                  | HTTP Status | Description                                                    |
| :-------------------- | :---------- | :------------------------------------------------------------- |
| **Authentication**    |             |                                                                |
| `MISSING_CREDENTIALS` | 400         | Email and password are required for login.                     |
| `INVALID_CREDENTIALS` | 401         | Incorrect email or password.                                   |
| `USER_UNVERIFIED`     | 403         | Email address is not verified yet.                             |
| `ACCOUNT_LOCKED`      | 429         | Account is temporarily locked due to too many failed attempts. |
| `UNAUTHORIZED_ACCESS` | 401         | Invalid or missing JWT token, or token expired.                |
| **Registration**      |             |                                                                |
| `MISSING_FIELDS`      | 400         | Required fields (email, password, names) are missing.          |
| `INVALID_INPUT`       | 400         | Input validation failed (e.g. name length).                    |
| `INVALID_EMAIL`       | 400         | Email format is invalid.                                       |
| `EMAIL_EXISTS`        | 409         | A user with this email address already exists.                 |
| `MAIL_SEND_FAILED`    | 500         | Failed to send the verification email.                         |
| **Verification**      |             |                                                                |
| `MISSING_TOKEN`       | 400         | Verification token is missing from the URL.                    |
| `INVALID_TOKEN`       | 400         | Verification token is invalid or has expired.                  |
| **System**            |             |                                                                |
| `UNKNOWN_ERROR`       | 500         | An unexpected error occurred.                                  |

### HTTP Status Codes Summary

- **400**: Validation Failed / Bad Request
- **401**: Unauthorized (Login failed or Token invalid)
- **403**: Forbidden (Unverified user or Insufficient permissions)
- **404**: Resource (Article/Category) Not Found
- **409**: Conflict (Duplicate Resource)
- **500**: Server Error
