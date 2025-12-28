<?php
// back-end-core/install.php

require __DIR__ . '/vendor/autoload.php';

use Dotenv\Dotenv;
use App\Database;

// Load Environment Variables
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

$db = new Database();
$conn = $db->connect();

if (!$conn) {
    die("Connection failed. Check your .env credentials.\n");
}

echo "Connected to database.\n";

// 1. Create Users Table
$sql = "CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'guest',
    verification_token VARCHAR(255) DEFAULT NULL,
    is_verified TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";

try {
    $conn->exec($sql);
    echo "Table 'users' created or already exists.\n";
} catch (PDOException $e) {
    die("Error creating table: " . $e->getMessage() . "\n");
}

// 2. Create Admin User
// Configure your default admin credentials here
$username = 'admin';
$email = 'admin@example.com';
$password = 'password123'; // CHANGE THIS! using a simple one for initial setup

// Check if admin already exists
$stmt = $conn->prepare("SELECT id FROM users WHERE username = :username OR email = :email");
$stmt->execute(['username' => $username, 'email' => $email]);

if ($stmt->fetch()) {
    echo "User '$username' (or email '$email') already exists. Skipping creation.\n";
} else {
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    
    $insert = $conn->prepare("INSERT INTO users (username, email, first_name, last_name, password_hash, role, is_verified) VALUES (:username, :email, 'Admin', 'User', :hash, 'admin', 1)");
    $insert->execute([
        'username' => $username,
        'email' => $email,
        'hash' => $passwordHash
    ]);
    
    echo "User '$username' created successfully.\n";
    echo "Email: $email\n";
    echo "Password: $password\n";
    echo "IMPORTANT: Please change this password later.\n";
}
