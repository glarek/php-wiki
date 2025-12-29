<?php
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use DI\ContainerBuilder;
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

// Controller Imports
use App\Controllers\AuthController;
use App\Controllers\WikiController;
use App\Controllers\Admin\CategoryController;
use App\Controllers\Admin\ArticleController;
use App\Controllers\Admin\UploadController;

require __DIR__ . '/../../back-end-core/vendor/autoload.php';

// Load Environment Variables
$dotenv = Dotenv::createImmutable(__DIR__ . '/../../back-end-core');
$dotenv->load();

// --- Container Setup (PHP-DI) ---
$containerBuilder = new ContainerBuilder();

$containerBuilder->addDefinitions([
    // Database Connection (Singleton)
    PDO::class => function () {
        $db = new Database();
        return $db->connect();
    },
    // Models (Auto-wired)
    // App\Article::class and App\Category::class are auto-wired because they type-hint PDO in constructor
]);

$container = $containerBuilder->build();

// Create App with Container
AppFactory::setContainer($container);
$app = AppFactory::create();

// Add Routing Middleware
$app->addRoutingMiddleware();

$app->addBodyParsingMiddleware();



// Middleware: Strip Trailing Slashes
$app->add(function (Request $request, $handler) {
    $uri = $request->getUri();
    $path = $uri->getPath();
    
    if ($path != '/' && substr($path, -1) == '/') {
        $path = rtrim($path, '/');
        $uri = $uri->withPath($path);
        $request = $request->withUri($uri);
    }
    
    return $handler->handle($request);
});

// Handle OPTIONS requests
$app->map(['OPTIONS'], '/{routes:.+}', function ($request, $response) {
    return $response;
});

// --- JWT Configuration ---
$jwtSecret = $_ENV['JWT_SECRET'];
$secret = new Secret($jwtSecret, 'HS256');
$decoder = new FirebaseDecoder($secret);

$options = new Options(
    attribute: 'token',       
    isSecure: true,           
    relaxed: ['localhost', '127.0.0.1', 'php-wiki.test'] 
);

$ignorePaths = ['/auth/login', '/test-db', '/debug-routing', '/wiki'];
if (isset($_ENV['APP_BASE_PATH'])) {
    $bp = rtrim($_ENV['APP_BASE_PATH'], '/');
    $ignorePaths[] = $bp . '/auth/login';
    $ignorePaths[] = $bp . '/test-db';
    $ignorePaths[] = $bp . '/debug-routing';
    $ignorePaths[] = $bp . '/wiki/menu';
    $ignorePaths[] = $bp . '/wiki/article';
    $ignorePaths[] = $bp . '/auth/register';
    $ignorePaths[] = $bp . '/auth/verify';
}
// Legacy/Hardcoded fallbacks
$ignorePaths[] = '/public_html/api/auth/login';
$ignorePaths[] = '/public_html/api/test-db';
$ignorePaths[] = '/public_html/api/wiki/menu';
$ignorePaths[] = '/public_html/api/wiki/article';
$ignorePaths[] = '/public_html/api/auth/register';
$ignorePaths[] = '/public_html/api/auth/verify';

$pathRule = new RequestPathRule(
    paths: ['/'], 
    ignore: array_unique($ignorePaths)
);
$methodRule = new RequestMethodRule(ignore: ['OPTIONS']);

$jwtMiddleware = new JwtAuthentication(
    $options,
    $decoder,
    [$methodRule, $pathRule]
);

$app->add($jwtMiddleware);

// --- Routes ---

// Auth
$app->post('/auth/register', [AuthController::class, 'register']);
$app->post('/auth/login', [AuthController::class, 'login']);
$app->get('/auth/verify', [AuthController::class, 'verify']);

// Middleware Import
use App\Middleware\AdminMiddleware;
use Slim\Routing\RouteCollectorProxy;

// ...

// Public Wiki
$app->get('/wiki/menu', [WikiController::class, 'getMenu']);
$app->get('/wiki/article/{slug}', [WikiController::class, 'getArticle']);

// Admin Routes Group
$app->group('/wiki', function (RouteCollectorProxy $group) {
    
    // Categories
    $group->post('/categories', [CategoryController::class, 'create']);
    $group->put('/categories/{id}', [CategoryController::class, 'update']);
    $group->delete('/categories/{id}', [CategoryController::class, 'delete']);

    // Articles
    $group->post('/articles', [ArticleController::class, 'create']);
    $group->put('/articles/{id}', [ArticleController::class, 'update']);
    $group->delete('/articles/{id}', [ArticleController::class, 'delete']);

    // Upload
    $group->post('/upload', [UploadController::class, 'upload']);

})->add(new AdminMiddleware());


// Root/Test Routes
$app->get('/', function (Request $request, Response $response) {
    $response->getBody()->write(json_encode(["status" => "API is running"]));
    return $response->withHeader('Content-Type', 'application/json');
});

$app->get('/test-db', function (Request $request, Response $response) {
    // We can verify DI here if we want!
    // But for quick check, manual connection:
    $db = new Database();
    $conn = $db->connect();
    $data = ["status" => $conn ? "connected" : "disconnected"];
    $response->getBody()->write(json_encode($data));
    return $response->withHeader('Content-Type', 'application/json');
});

// Set base path
if (isset($_ENV['APP_BASE_PATH'])) {
    $app->setBasePath($_ENV['APP_BASE_PATH']);
}

// Custom Error Handler
$displayErrorDetails = filter_var($_ENV['APP_DEBUG'] ?? false, FILTER_VALIDATE_BOOLEAN);
$logErrors = true;
$logErrorDetails = true;

$errorMiddleware = $app->addErrorMiddleware($displayErrorDetails, $logErrors, $logErrorDetails);
$errorMiddleware->setErrorHandler(
    AuthorizationException::class,
    function (Request $request, Throwable $exception, bool $displayErrorDetails, bool $logErrors, bool $logErrorDetails) use ($app) {
        $response = $app->getResponseFactory()->createResponse();
        $payload = ["status" => "error", "message" => $exception->getMessage()];
        $response->getBody()->write(json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
        return $response->withStatus(401)->withHeader("Content-Type", "application/json");
    }
);

// Default Error Handler (Catches all other exceptions)
$errorMiddleware->setDefaultErrorHandler(
    function (Request $request, Throwable $exception, bool $displayErrorDetails, bool $logErrors, bool $logErrorDetails) use ($app) {
        $response = $app->getResponseFactory()->createResponse();
        
        $statusCode = 500;
        if (is_int($exception->getCode()) && $exception->getCode() >= 400 && $exception->getCode() < 600) {
            $statusCode = $exception->getCode();
        }

        $payload = [
            'status' => 'error',
            'message' => $exception->getMessage()
        ];
        
        if ($displayErrorDetails) {
            $payload['trace'] = $exception->getTraceAsString();
        }

        $response->getBody()->write(json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
        return $response->withStatus($statusCode)->withHeader('Content-Type', 'application/json');
    }
);


// CORS Middleware (Must be added last to execute first and handle errors/JWT)
$app->add(function (Request $request, $handler) {
    $response = $handler->handle($request);
    return $response
        ->withHeader('Access-Control-Allow-Origin', '*')
        ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
});

$app->run();
