<?php
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use Dotenv\Dotenv;
use App\Database;

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

// Set base path for current local setup (Project Root is DocumentRoot)
$app->setBasePath('/public_html/api'); 

$app->addBodyParsingMiddleware();

// CORS Middleware
$app->add(function (Request $request, $handler) {
    if ($request->getMethod() === 'OPTIONS') {
        // Handle OPTIONS explicitly to ensure correct headers are sent even if auth is skipped
        $response = $handler->handle($request);
    } else {
        $response = $handler->handle($request);
    }
    
    return $response
        ->withHeader('Access-Control-Allow-Origin', '*')
        ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
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
$pathRule = new RequestPathRule(
    paths: ['/'], 
    ignore: ['/auth/login', '/test-db', '/public_html/api/auth/login', '/public_html/api/test-db']
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

$app->addRoutingMiddleware();

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

$app->run();
