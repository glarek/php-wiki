<?php

namespace App\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use PDO;
use Exception;
use Firebase\JWT\JWT;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as MailerException;

class AuthController
{
    private PDO $conn;

    public function __construct(PDO $conn)
    {
        $this->conn = $conn;
    }

    public function login(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        $username = $data['username'] ?? null;
        $password = $data['password'] ?? null;

        if (!$username || !$password) {
            $payload = json_encode(["status" => "error", "message" => "Username and password required"]);
            $response->getBody()->write($payload);
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $stmt = $this->conn->prepare("SELECT id, username, password_hash, role, is_verified FROM users WHERE username = :username");
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password_hash'])) {
            
            // Verification Check
            if ((int)$user['is_verified'] !== 1) {
                $response->getBody()->write(json_encode(["status" => "error", "message" => "Please verify your email address before logging in."]));
                return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
            }

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
    }

    public function register(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        $username = trim($data['username'] ?? '');
        $password = $data['password'] ?? '';
        $email = trim($data['email'] ?? '');

        if (empty($username) || empty($password) || empty($email)) {
            throw new Exception("Username, password, and email are required", 400);
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new Exception("Invalid email address", 400);
        }

        // Check availability
        $stmt = $this->conn->prepare("SELECT id FROM users WHERE username = :username OR email = :email");
        $stmt->execute(['username' => $username, 'email' => $email]);
        if ($stmt->fetch()) {
            throw new Exception("Username or email already exists", 409);
        }

        // Create User
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
        $verificationToken = bin2hex(random_bytes(32));
        
        $stmt = $this->conn->prepare("INSERT INTO users (username, password_hash, email, role, verification_token, is_verified) VALUES (:username, :hash, :email, 'guest', :token, 0)");
        $stmt->execute([
            'username' => $username,
            'hash' => $passwordHash,
            'email' => $email,
            'token' => $verificationToken
        ]);

        // Send Email via PHPMailer
        try {
            $this->sendVerificationEmail($email, $username, $verificationToken, $request);
        } catch (MailerException $e) {
            // Mail failed, so we must delete the user to prevent "zombie" accounts
            $cleanup = $this->conn->prepare("DELETE FROM users WHERE username = :username");
            $cleanup->execute(['username' => $username]);
            
            $hostInfo = $_ENV['SMTP_HOST'] . ':' . $_ENV['SMTP_PORT'];
            throw new Exception("Registration failed: Email could not be sent (Host: $hostInfo). Error: {$e->getMessage()}", 500);
        }

        $response->getBody()->write(json_encode([
            "status" => "success", 
            "message" => "Registration successful. Please check your email for the verification link."
        ]));
        return $response->withStatus(201)->withHeader('Content-Type', 'application/json');
    }

    public function verify(Request $request, Response $response): Response
    {
        $token = $request->getQueryParams()['token'] ?? null;

        if (!$token) {
            throw new Exception("Missing verification token", 400);
        }

        $stmt = $this->conn->prepare("SELECT id FROM users WHERE verification_token = :token AND is_verified = 0");
        $stmt->execute(['token' => $token]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            throw new Exception("Invalid or expired verification token", 400);
        }

        // Verify User
        $update = $this->conn->prepare("UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = :id");
        $update->execute(['id' => $user['id']]);

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Account verified successfully. You can now login."]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    private function sendVerificationEmail($email, $username, $token, Request $request)
    {
         // Send Email via PHPMailer
         $host = $_SERVER['HTTP_HOST'] ?? 'api.tryckfall.nu';
         $basePath = $_ENV['APP_BASE_PATH'] ?? '/api';
         $verifyUrl = "https://" . $host . $basePath . "/auth/verify?token=" . $token;
 
         $mail = new PHPMailer(true);
 
         // Server settings
         $mail->isSMTP();
         $mail->Host       = $_ENV['SMTP_HOST'];
         $mail->SMTPAuth   = true;
         $mail->Username   = $_ENV['SMTP_USER'];
         $mail->Password   = $_ENV['SMTP_PASS'];
         
         $port = (int)$_ENV['SMTP_PORT'];
         $mail->Port = $port;
 
         if ($port === 587) {
             $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
         } elseif ($port === 465) {
             $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
         }
 
         // Recipients
         $mail->setFrom($_ENV['SMTP_USER'], 'Tryckfall API');
         $mail->addAddress($email, $username);
 
         // Content
         $mail->isHTML(true);
         $mail->Subject = 'Verify your account at Tryckfall';
         $mail->Body    = "
             <h1>Welcome to Tryckfall!</h1>
             <p>Hi $username,</p>
             <p>Please click the button below to verify your account:</p>
             <p><a href='$verifyUrl' style='background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>Verify Email</a></p>
             <p>Or copy this link: $verifyUrl</p>
             <br>
             <p>Best regards,<br>Tryckfall Team</p>
         ";
         $mail->AltBody = "Hi $username,\n\nPlease verify your account: $verifyUrl\n\nBest regards,\nTryckfall Team";
 
         $mail->send();
    }
}
