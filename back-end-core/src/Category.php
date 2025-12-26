<?php
namespace App;

use PDO;

class Category
{
    private PDO $conn;

    public function __construct(PDO $conn)
    {
        $this->conn = $conn;
    }

    // Get all categories ordered by sort_order
    public function getAll(): array
    {
        $stmt = $this->conn->query("SELECT * FROM categories ORDER BY sort_order ASC, name ASC");
        return $stmt->fetchAll();
    }
}
