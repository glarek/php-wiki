<?php

namespace App\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use PDO;
use Exception;
use Firebase\JWT\JWT;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as MailerException;
use App\Exceptions\AppException;

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
        $email = $data['email'] ?? null;
        $password = $data['password'] ?? null;

        if (!$email || !$password) {
            throw new AppException("Email and password required", 400, "MISSING_CREDENTIALS");
        }

        $stmt = $this->conn->prepare("SELECT id, email, password_hash, role, is_verified, first_name, last_name, failed_login_attempts, locked_until FROM users WHERE email = :email");
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // Security: Always delay slightly to mitigate timing attacks on existence check
        usleep(rand(100000, 300000)); // 100ms - 300ms

        if (!$user) {
             throw new AppException("Invalid credentials", 401, "INVALID_CREDENTIALS");
        }

        // Check Lockout
        if ($user['locked_until'] && strtotime($user['locked_until']) > time()) {
             $wait = strtotime($user['locked_until']) - time();
             $minutes = ceil($wait / 60);
             throw new AppException("Account is temporarily locked due to too many failed attempts. Try again in $minutes minutes.", 429, "ACCOUNT_LOCKED");
        }

        if (password_verify($password, $user['password_hash'])) {
            
            // Verification Check
            if ((int)$user['is_verified'] !== 1) {
                throw new AppException("Please verify your email address before logging in.", 403, "USER_UNVERIFIED");
            }

            // Reset failed attempts on success
            $reset = $this->conn->prepare("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = :id");
            $reset->execute(['id' => $user['id']]);

            // Generate JWT
            $issuedAt = time();
            $expirationTime = $issuedAt + 3600; // valid for 1 hour
            // Add custom name claim for frontend display
            $payload = [
                'iat' => $issuedAt,
                'exp' => $expirationTime,
                'sub' => $user['id'],
                'first_name' => $user['first_name'],
                'last_name' => $user['last_name'],
                'role' => $user['role']
            ];

            $jwt = JWT::encode($payload, $_ENV['JWT_SECRET'], 'HS256');

            // Generate Refresh Token
            $refreshToken = bin2hex(random_bytes(32));
            $refreshTokenHash = hash('sha256', $refreshToken);
            $refreshTokenExpiry = date('Y-m-d H:i:s', time() + 604800); // 7 days

            // Store Refresh Token
            $stmt = $this->conn->prepare("INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (:hash, :uid, :expiry)");
            $stmt->execute([
                'hash' => $refreshTokenHash,
                'uid' => $user['id'],
                'expiry' => $refreshTokenExpiry
            ]);

            $response->getBody()->write(json_encode([
                "status" => "success",
                "token" => $jwt,
                "refresh_token" => $refreshToken,
                "user" => [
                    "first_name" => $user['first_name'],
                    "last_name" => $user['last_name'],
                    "email" => $user['email'],
                    "role" => $user['role']
                ]
            ]));
            return $response->withHeader('Content-Type', 'application/json');
        }

        // Handle Failed Attempt
        $failedAttempts = (int)$user['failed_login_attempts'] + 1;
        $lockedUntil = null;
        
        // Progressive Delays (simulated via sleep for immediate response, or lockout for future)
        if ($failedAttempts >= 5) {
            // Lockout for 15 minutes after 5th attempt
             $lockedUntil = date('Y-m-d H:i:s', time() + 900);
        } elseif ($failedAttempts >= 3) {
            sleep(5); // Delay 5s
        }

        $update = $this->conn->prepare("UPDATE users SET failed_login_attempts = :attempts, locked_until = :locked WHERE id = :id");
        $update->execute([
            'attempts' => $failedAttempts,
            'locked' => $lockedUntil,
            'id' => $user['id']
        ]);

        throw new AppException("Invalid credentials", 401, "INVALID_CREDENTIALS");
    }

    public function refreshToken(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        $refreshToken = $data['refresh_token'] ?? null;

        if (!$refreshToken) {
            throw new AppException("Refresh token required", 400, "MISSING_TOKEN");
        }

        $refreshTokenHash = hash('sha256', $refreshToken);

        // Find token and check expiry
        $stmt = $this->conn->prepare("
            SELECT rt.id, rt.user_id, rt.expires_at, u.first_name, u.last_name, u.email, u.role, u.is_verified 
            FROM refresh_tokens rt
            JOIN users u ON rt.user_id = u.id
            WHERE rt.token_hash = :hash AND rt.expires_at > NOW()
        ");
        $stmt->execute(['hash' => $refreshTokenHash]);
        $tokenData = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$tokenData) {
            throw new AppException("Invalid or expired refresh token", 401, "INVALID_REFRESH_TOKEN");
        }

        // Verify User State (e.g. not banned, verified)
        if ((int)$tokenData['is_verified'] !== 1) {
             throw new AppException("User is not verified", 403, "USER_UNVERIFIED");
        }

        // Token Rotation: Delete the used token
        $del = $this->conn->prepare("DELETE FROM refresh_tokens WHERE id = :id");
        $del->execute(['id' => $tokenData['id']]);

        // Generate NEW Tokens
        $issuedAt = time();
        $expirationTime = $issuedAt + 3600; // 1 hr Access Token
        
        $payload = [
            'iat' => $issuedAt,
            'exp' => $expirationTime,
            'sub' => $tokenData['user_id'],
            'first_name' => $tokenData['first_name'],
            'last_name' => $tokenData['last_name'],
            'role' => $tokenData['role']
        ];
        
        $newJwt = JWT::encode($payload, $_ENV['JWT_SECRET'], 'HS256');

        $newRefreshToken = bin2hex(random_bytes(32));
        $newRefreshTokenHash = hash('sha256', $newRefreshToken);
        $newRefreshTokenExpiry = date('Y-m-d H:i:s', time() + 604800); // 7 days

        $ins = $this->conn->prepare("INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (:hash, :uid, :expiry)");
        $ins->execute([
            'hash' => $newRefreshTokenHash,
            'uid' => $tokenData['user_id'],
            'expiry' => $newRefreshTokenExpiry
        ]);

        $response->getBody()->write(json_encode([
            "status" => "success",
            "token" => $newJwt,
            "refresh_token" => $newRefreshToken
        ]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function register(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        $password = $data['password'] ?? '';
        $email = trim($data['email'] ?? '');
        $firstName = trim($data['first_name'] ?? '');
        $lastName = trim($data['last_name'] ?? '');

        if (empty($password) || empty($email) || empty($firstName) || empty($lastName)) {
            throw new AppException("Password, email, first name, and last name are required", 400, "MISSING_FIELDS");
        }

        if (strlen($firstName) < 1 || strlen($lastName) < 1) {
             throw new AppException("First name and last name must be at least 1 character long", 400, "INVALID_INPUT");
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new AppException("Invalid email address", 400, "INVALID_EMAIL");
        }

        // Check availability
        $stmt = $this->conn->prepare("SELECT id FROM users WHERE email = :email");
        $stmt->execute(['email' => $email]);
        if ($stmt->fetch()) {
            throw new AppException("Email already exists", 409, "EMAIL_EXISTS");
        }

        // Create User
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
        
        $verificationTokenRaw = bin2hex(random_bytes(32));
        $verificationTokenHash = hash('sha256', $verificationTokenRaw);
        $verificationTokenExpiry = date('Y-m-d H:i:s', time() + 86400); // 24 hours

        $stmt = $this->conn->prepare("INSERT INTO users (password_hash, email, first_name, last_name, role, verification_token, verification_token_expires_at, is_verified) VALUES (:hash, :email, :first_name, :last_name, 'guest', :token, :expiry, 0)");
        $stmt->execute([
            'hash' => $passwordHash,
            'email' => $email,
            'first_name' => $firstName,
            'last_name' => $lastName,
            'token' => $verificationTokenHash,
            'expiry' => $verificationTokenExpiry
        ]);

        // Send Email via PHPMailer
        try {
            $this->sendVerificationEmail($email, $verificationTokenRaw, $request);
        } catch (MailerException $e) {
            // Mail failed, so we must delete the user to prevent "zombie" accounts
            $cleanup = $this->conn->prepare("DELETE FROM users WHERE email = :email");
            $cleanup->execute(['email' => $email]);
            
            $hostInfo = $_ENV['SMTP_HOST'] . ':' . $_ENV['SMTP_PORT'];
            throw new AppException("Registration failed: Email could not be sent (Host: $hostInfo). Error: {$e->getMessage()}", 500, "MAIL_SEND_FAILED");
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
            throw new AppException("Missing verification token", 400, "MISSING_TOKEN");
        }

        $tokenHash = hash('sha256', $token);

        $stmt = $this->conn->prepare("SELECT id FROM users WHERE verification_token = :token AND verification_token_expires_at > NOW() AND is_verified = 0");
        $stmt->execute(['token' => $tokenHash]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            throw new AppException("Invalid or expired verification token", 400, "INVALID_TOKEN");
        }

        // Verify User
        $update = $this->conn->prepare("UPDATE users SET is_verified = 1, verification_token = NULL, verification_token_expires_at = NULL WHERE id = :id");
        $update->execute(['id' => $user['id']]);

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Account verified successfully. You can now login."]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    private function sendVerificationEmail($email, $token, Request $request)
    {
         // Send Email via PHPMailer
         $frontendUrl = $_ENV['FRONTEND_URL'] ?? 'http://localhost:5173';
         $verifyUrl = rtrim($frontendUrl, '/') . "/verifikation-lyckad?token=" . $token;
 
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
         $mail->addAddress($email);
 
         // Content
         $mail->isHTML(true);
         $mail->Subject = 'Verify your account at Tryckfall';
         $mail->Body    = "
             <h1>Welcome to Tryckfall!</h1>
             <p>Hi,</p>
             <p>Please click the button below to verify your account:</p>
             <p><a href='$verifyUrl' style='background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>Verify Email</a></p>
             <p>Or copy this link: $verifyUrl</p>
             <br>
             <p>Best regards,<br>Tryckfall Team</p>
         ";
         $mail->AltBody = "Hi,\n\nPlease verify your account: $verifyUrl\n\nBest regards,\nTryckfall Team";
 
         $mail->send();
    }

    public function forgotPassword(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        $email = $data['email'] ?? '';
        
        // Generic response closure to prevent duplication and ensure timing attack resistance (conceptually)
        $genericResponse = function() use ($response) {
            $response->getBody()->write(json_encode([
                "status" => "success", 
                "message" => "If the email exists in our system, a password reset link has been sent."
            ]));
            return $response->withHeader('Content-Type', 'application/json');
        };

        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return $genericResponse();
        }

        $stmt = $this->conn->prepare("SELECT id FROM users WHERE email = :email");
        $stmt->execute(['email' => $email]);
        if (!$stmt->fetch()) {
            return $genericResponse();
        }

        // Generate Token
        $tokenRaw = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $tokenRaw);
        // Expiry: 30 minutes from now
        $expiry = date('Y-m-d H:i:s', time() + 1800); 

        $update = $this->conn->prepare("UPDATE users SET reset_token = :token, reset_token_expires_at = :expiry WHERE email = :email");
        $update->execute([
            'token' => $tokenHash,
            'expiry' => $expiry,
            'email' => $email
        ]);

        // Send Email
        try {
            $this->sendResetEmail($email, $tokenRaw);
        } catch (MailerException $e) {
            // Check if we are in dev/debug mode to potentially show error, 
            // otherwise just log it and show generic success.
            // For this implementation, we log to error_log.
            error_log("Failed to send reset email to $email: " . $e->getMessage());
        }

        return $genericResponse();
    }

    public function resetPassword(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        $token = $data['token'] ?? '';
        $newPassword = $data['password'] ?? '';

        if (empty($token) || empty($newPassword)) {
            throw new AppException("Token and new password are required", 400, "MISSING_FIELDS");
        }

        $tokenHash = hash('sha256', $token);

        $stmt = $this->conn->prepare("SELECT id FROM users WHERE reset_token = :token AND reset_token_expires_at > NOW()");
        $stmt->execute(['token' => $tokenHash]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            throw new AppException("Invalid or expired token", 400, "INVALID_TOKEN");
        }

        $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);

        // Update password and clear token
        $update = $this->conn->prepare("UPDATE users SET password_hash = :hash, reset_token = NULL, reset_token_expires_at = NULL WHERE id = :id");
        $update->execute([
            'hash' => $passwordHash,
            'id' => $user['id']
        ]);

        $response->getBody()->write(json_encode([
            "status" => "success", 
            "message" => "Password has been reset successfully. You can now login."
        ]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    private function sendResetEmail($email, $token)
    {
         // Send Email via PHPMailer
         // Note: Frontend URL should be configurable. Assuming standard /reset-password route on frontend.
         // $host = $_SERVER['HTTP_HOST'] ?? 'tryckfall.nu'; // This might be API host?
         // We need the FRONTEND host. Often passed in header or ENV.
         // Let's assume the frontend is receiving this token.
         
         // User requested: "https://dindomän.se/reset-password?token=DEN_OKRYPTERADE_STRÄNGEN"
         // I'll try to guess the frontend URL from Referer or Origin, or just use a placeholder/ENV.
         // Given usage of 'localhost', I'll assume standard FE port or same domain.
         
         $frontendUrl = $_ENV['FRONTEND_URL'] ?? 'http://localhost:5173'; // Default Vite port
         $resetUrl = rtrim($frontendUrl, '/') . "/reset-password?token=" . $token;
 
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
         $mail->setFrom($_ENV['SMTP_USER'], 'Tryckfall Support');
         $mail->addAddress($email);
 
         // Content
         $mail->isHTML(true);
         $mail->Subject = 'Reset your password';
         $mail->Body    = "
             <h1>Password Reset Request</h1>
             <p>Hi,</p>
             <p>We received a request to reset your password. Click the link below to set a new password:</p>
             <p><a href='$resetUrl'>$resetUrl</a></p>
             <p>This link is valid for 30 minutes.</p>
             <p>If you didn't request this, please ignore this email.</p>
             <br>
             <p>Best regards,<br>Tryckfall Team</p>
         ";
         $mail->AltBody = "Hi,\n\nReset your password here: $resetUrl\n\nIf you didn't request this, ignore this email.";
 
         $mail->send();
    }
}
