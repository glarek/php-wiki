<?php
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use Dotenv\Dotenv;
use App\Database;
use App\Category;
use App\Article;

// JwtAuth Imports
use JimTools\JwtAuth\Middleware\JwtAuthentication;
use JimTools\JwtAuth\Options;
use JimTools\JwtAuth\Secret;
use JimTools\JwtAuth\Decoder\FirebaseDecoder;
use JimTools\JwtAuth\Rules\RequestPathRule;
use JimTools\JwtAuth\Rules\RequestMethodRule;
use JimTools\JwtAuth\Exceptions\AuthorizationException;
use Firebase\JWT\JWT;

require __DIR__ . '/../../back-end-core/vendor/autoload.php';

// Load Environment Variables
$dotenv = Dotenv::createImmutable(__DIR__ . '/../../back-end-core');
$dotenv->load();

// Create App
$app = AppFactory::create();

// Add Routing Middleware (Must be added early to execute LATE in LIFO stack)
$app->addRoutingMiddleware();

// Set base path (Dynamic from .env, or null if root)
if (isset($_ENV['APP_BASE_PATH'])) {
    $app->setBasePath($_ENV['APP_BASE_PATH']);
}

$app->addBodyParsingMiddleware();

// CORS Middleware
$app->add(function (Request $request, $handler) {
    $response = $handler->handle($request);
    return $response
        ->withHeader('Access-Control-Allow-Origin', '*')
        ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
});

// Middleware: Strip Trailing Slashes
$app->add(function (Request $request, $handler) {
    $uri = $request->getUri();
    $path = $uri->getPath();
    
    if ($path != '/' && substr($path, -1) == '/') {
        $path = rtrim($path, '/'); // recursive remove is also fine: rtrim($path, '/')
        $uri = $uri->withPath($path);
        $request = $request->withUri($uri);
    }
    
    return $handler->handle($request);
});

// Handle OPTIONS requests separately to avoid 405 errors
$app->map(['OPTIONS'], '/{routes:.+}', function ($request, $response) {
    return $response;
});

// Configure JWT Middleware
$jwtSecret = $_ENV['JWT_SECRET'];
$secret = new Secret($jwtSecret, 'HS256');
$decoder = new FirebaseDecoder($secret);

$options = new Options(
    attribute: 'token',       // Attribute name in Request object
    isSecure: true,           // Require HTTPS (relaxed for localhost)
    relaxed: ['localhost', '127.0.0.1', 'php-wiki.test'] 
);

// Rules: Check paths, ignore login/test
$ignorePaths = ['/auth/login', '/test-db', '/debug-routing', '/wiki'];

// Add Base Path variants if dynamic base path is set
if (isset($_ENV['APP_BASE_PATH'])) {
    $bp = rtrim($_ENV['APP_BASE_PATH'], '/');
    $ignorePaths[] = $bp . '/auth/login';
    $ignorePaths[] = $bp . '/test-db';
    $ignorePaths[] = $bp . '/debug-routing';
    // Only ignore PUBLIC Wiki routes (Menu & Articles)
    // Do NOT ignore /wiki/categories which implies Admin ops!
    $ignorePaths[] = $bp . '/wiki/menu';
    $ignorePaths[] = $bp . '/wiki/article';
}

// Legacy/Hardcoded fallbacks for local dev
$ignorePaths[] = '/public_html/api/auth/login';
$ignorePaths[] = '/public_html/api/test-db';
$ignorePaths[] = '/public_html/api/wiki/menu';
$ignorePaths[] = '/public_html/api/wiki/article';
$ignorePaths[] = '/public_html/api/auth/login';
$ignorePaths[] = '/public_html/api/test-db';

$pathRule = new RequestPathRule(
    paths: ['/'], 
    ignore: array_unique($ignorePaths)
);
// Rule: Ignore OPTIONS method for CORS
$methodRule = new RequestMethodRule(ignore: ['OPTIONS']);

$jwtMiddleware = new JwtAuthentication(
    $options,
    $decoder,
    [$methodRule, $pathRule]
);

$app->add($jwtMiddleware);

// Login Route
$app->post('/auth/login', function (Request $request, Response $response) {
    $data = $request->getParsedBody();
    $username = $data['username'] ?? null;
    $password = $data['password'] ?? null;

    if (!$username || !$password) {
        $payload = json_encode(["status" => "error", "message" => "Username and password required"]);
        $response->getBody()->write($payload);
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
    }

    $db = new Database();
    $conn = $db->connect();

    $stmt = $conn->prepare("SELECT id, username, password_hash, role FROM users WHERE username = :username");
    $stmt->execute(['username' => $username]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password_hash'])) {
        // Generate JWT
        $issuedAt = time();
        $expirationTime = $issuedAt + 3600; // valid for 1 hour
        $payload = [
            'iat' => $issuedAt,
            'exp' => $expirationTime,
            'sub' => $user['id'],
            'user' => $user['username'],
            'role' => $user['role']
        ];

        $jwt = JWT::encode($payload, $_ENV['JWT_SECRET'], 'HS256');

        $response->getBody()->write(json_encode([
            "status" => "success",
            "token" => $jwt,
            "user" => [
                "username" => $user['username'],
                "role" => $user['role']
            ]
        ]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    $response->getBody()->write(json_encode(["status" => "error", "message" => "Invalid credentials"]));
    return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
});

// Routing Middleware moved to top
// $app->addRoutingMiddleware();

// Error Middleware with Custom Handler for JWT Auth Failures
$errorMiddleware = $app->addErrorMiddleware(true, true, true);

$errorMiddleware->setErrorHandler(
    AuthorizationException::class,
    function (Request $request, Throwable $exception, bool $displayErrorDetails, bool $logErrors, bool $logErrorDetails) use ($app) {
        $response = $app->getResponseFactory()->createResponse();
        $payload = [
            "status" => "error",
            "message" => $exception->getMessage()
        ];
        
        $response->getBody()->write(json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
        return $response
            ->withStatus(401)
            ->withHeader("Content-Type", "application/json");
    }
);

// Root Route
$app->get('/', function (Request $request, Response $response) {
    $response->getBody()->write(json_encode(["status" => "API is running"]));
    return $response->withHeader('Content-Type', 'application/json');
});

// Test Route
$app->get('/test-db', function (Request $request, Response $response) {
    $db = new Database();
    $conn = $db->connect();

    $data = ["status" => "disconnected"];
    if ($conn) {
        $data = ["status" => "connected"];
    }

    $response->getBody()->write(json_encode($data));
    return $response->withHeader('Content-Type', 'application/json');
});

// --- Wiki API Routes (Public) ---

// GET /wiki/menu - Returns the sidebar menu structure
$app->get('/wiki/menu', function (Request $request, Response $response) {
    try {
        $db = new Database();
        $conn = $db->connect();
        $articleModel = new Article($conn);
        $menu = $articleModel->getMenuStructure();

        $response->getBody()->write(json_encode(["status" => "success", "data" => $menu]));
        return $response->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $payload = json_encode(["status" => "error", "message" => $e->getMessage()]);
        $response->getBody()->write($payload);
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }
});

// GET /wiki/article/{slug} - Returns a single article
$app->get('/wiki/article/{slug}', function (Request $request, Response $response, $args) {
    $slug = $args['slug'];
    
    try {
        $db = new Database();
        $conn = $db->connect();
        $articleModel = new Article($conn);
        $article = $articleModel->getBySlug($slug);

        if (!$article) {
            $payload = json_encode(["status" => "error", "message" => "Article not found"]);
            $response->getBody()->write($payload);
            return $response->withStatus(404)->withHeader('Content-Type', 'application/json');
        }

        $response->getBody()->write(json_encode(["status" => "success", "data" => $article]));
        return $response->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $payload = json_encode(["status" => "error", "message" => $e->getMessage()]);
        $response->getBody()->write($payload);
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }
});

// --- Admin Category Routes (Protected) ---

// Helper function to validate admin role
// Helper function to validate admin role
$checkAdmin = function (Request $request) {
    $token = $request->getAttribute('token'); // 'token' attribute set by JwtAuth
    
    // Debugging: Check what we actually got
    $role = $token['role'] ?? 'MISSING';
    
    if (!$token || $role !== 'admin') {
        // Return detailed error for debugging
        $dump = json_encode($token);
        throw new Exception("Unauthorized: Admin access required. Found role: '{$role}'. Full Token: {$dump}", 403);
    }
};

// POST /wiki/categories - Create Category
$app->post('/wiki/categories', function (Request $request, Response $response) use ($checkAdmin) {
    try {
        $checkAdmin($request); // Verify Admin

        $data = $request->getParsedBody();
        $name = trim($data['name'] ?? '');
        $slug = trim($data['slug'] ?? '');
        $sortOrder = (int) ($data['sort_order'] ?? 0);

        // 1. Validation
        if (empty($name) || empty($slug)) {
            throw new Exception("Name and Slug are required", 400);
        }

        // Sanitize Name (Strip Tags)
        $name = strip_tags($name);

        // Validate Slug (Lowercase, alphanumeric, hyphens only)
        $slug = strtolower($slug);
        if (!preg_match('/^[a-z0-9-]+$/', $slug)) {
            throw new Exception("Invalid slug format. Use only lowercase letters, numbers, and hyphens.", 400);
        }

        $db = new Database();
        $conn = $db->connect();
        $categoryModel = new Category($conn);

        // 2. Check for Duplicates (Name or Slug)
        if ($categoryModel->exists($slug)) {
            throw new Exception("A category with this slug already exists.", 409); // 409 Conflict
        }

        // 3. Create
        $id = $categoryModel->create($name, $slug, $sortOrder);

        $response->getBody()->write(json_encode(["status" => "success", "data" => ["id" => $id]]));
        return $response->withStatus(201)->withHeader('Content-Type', 'application/json');

    } catch (Exception $e) {
        $status = $e->getCode() && $e->getCode() >= 400 && $e->getCode() < 600 ? $e->getCode() : 500;
        $payload = json_encode(["status" => "error", "message" => $e->getMessage()]);
        $response->getBody()->write($payload);
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
});

// PUT /wiki/categories/{id} - Update Category
$app->put('/wiki/categories/{id}', function (Request $request, Response $response, $args) use ($checkAdmin) {
    try {
        $checkAdmin($request);

        $id = (int) $args['id'];
        $data = $request->getParsedBody();
        $name = trim($data['name'] ?? '');
        $slug = trim($data['slug'] ?? '');
        $sortOrder = (int) ($data['sort_order'] ?? 0);

        if (empty($name) || empty($slug)) {
            throw new Exception("Name and Slug are required", 400);
        }

        $name = strip_tags($name);
        $slug = strtolower($slug);
        if (!preg_match('/^[a-z0-9-]+$/', $slug)) {
            throw new Exception("Invalid slug format.", 400);
        }

        $db = new Database();
        $conn = $db->connect();
        $categoryModel = new Category($conn);

        // Check availability (exclude current ID)
        if ($categoryModel->exists($slug, $id)) {
            throw new Exception("Slug is already in use by another category.", 409);
        }

        // Check if category exists
        if (!$categoryModel->findById($id)) {
            throw new Exception("Category not found", 404);
        }

        $categoryModel->update($id, $name, $slug, $sortOrder);

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Category updated"]));
        return $response->withHeader('Content-Type', 'application/json');

    } catch (Exception $e) {
        $status = $e->getCode() && $e->getCode() >= 400 && $e->getCode() < 600 ? $e->getCode() : 500;
        $payload = json_encode(["status" => "error", "message" => $e->getMessage()]);
        $response->getBody()->write($payload);
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
});

// DELETE /wiki/categories/{id} - Delete Category
$app->delete('/wiki/categories/{id}', function (Request $request, Response $response, $args) use ($checkAdmin) {
    try {
        $checkAdmin($request);
        $id = (int) $args['id'];

        $db = new Database();
        $conn = $db->connect();
        $categoryModel = new Category($conn);

        if (!$categoryModel->findById($id)) {
            throw new Exception("Category not found", 404);
        }

        $categoryModel->delete($id);

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Category deleted"]));
        return $response->withHeader('Content-Type', 'application/json');

    } catch (Exception $e) {
        $status = $e->getCode() && $e->getCode() >= 400 && $e->getCode() < 600 ? $e->getCode() : 500;
        $payload = json_encode(["status" => "error", "message" => $e->getMessage()]);
        $response->getBody()->write($payload);
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
});

$app->run();
