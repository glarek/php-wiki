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
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function findById(int $id): ?array
    {
        $stmt = $this->conn->prepare("SELECT * FROM categories WHERE id = :id");
        $stmt->execute(['id' => $id]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result ?: null;
    }

    public function exists(string $slug, ?int $excludeId = null): bool
    {
        $sql = "SELECT COUNT(*) FROM categories WHERE slug = :slug";
        $params = ['slug' => $slug];

        if ($excludeId) {
            $sql .= " AND id != :id";
            $params['id'] = $excludeId;
        }

        $stmt = $this->conn->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchColumn() > 0;
    }

    public function create(string $name, string $slug, int $sortOrder = 0): int
    {
        $stmt = $this->conn->prepare("INSERT INTO categories (name, slug, sort_order) VALUES (:name, :slug, :sort_order)");
        $stmt->execute([
            'name' => $name,
            'slug' => $slug,
            'sort_order' => $sortOrder
        ]);
        return (int) $this->conn->lastInsertId();
    }

    public function update(int $id, string $name, string $slug, int $sortOrder): bool
    {
        $stmt = $this->conn->prepare("UPDATE categories SET name = :name, slug = :slug, sort_order = :sort_order WHERE id = :id");
        return $stmt->execute([
            'id' => $id,
            'name' => $name,
            'slug' => $slug,
            'sort_order' => $sortOrder
        ]);
    }

    public function delete(int $id): bool
    {
        // Articles will cascade delete due to foreign key constraint
        $stmt = $this->conn->prepare("DELETE FROM categories WHERE id = :id");
        return $stmt->execute(['id' => $id]);
    }
}
