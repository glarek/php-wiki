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
    "token": "eyJhbGciOiJIUzI1Ni...", // Store this JWT
    "user": { "name": "John Doe", "email": "john@example.com", "role": "guest" }
  }
  ```
- **Note**: Returns `403` if account is not verified.

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
  "message": "Human readable error description"
}
```

- **400**: Validation Failed (e.g. Invalid Email, Missing Fields)
- **401**: Missing or Invalid Token
- **403**: Forbidden (Not Admin, or Unverified)
- **404**: Resource (Article/Category) Not Found
- **409**: Duplicate Resource (Slug/Username taken)
