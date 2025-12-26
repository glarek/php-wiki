<?php
namespace App;

use PDO;

class Article
{
    private PDO $conn;

    public function __construct(PDO $conn)
    {
        $this->conn = $conn;
    }

    // Get a single article by slug with author details
    public function getBySlug(string $slug): ?array
    {
        $stmt = $this->conn->prepare("
            SELECT 
                a.*, 
                c.name as category_name, 
                c.slug as category_slug,
                u.username as author_name 
            FROM articles a
            JOIN categories c ON a.category_id = c.id
            LEFT JOIN users u ON a.author_id = u.id
            WHERE a.slug = :slug
        ");
        $stmt->execute(['slug' => $slug]);
        $result = $stmt->fetch();
        return $result ?: null;
    }

    // Get articles grouped by category for the menu
    // Returns: [ category_id => [category_info, articles => []] ]
    public function getMenuStructure(): array
    {
        // 1. Get all categories
        $categories = $this->conn->query("SELECT id, name, slug FROM categories ORDER BY sort_order ASC")->fetchAll();
        
        // 2. Get all articles (only id, title, slug, category_id)
        $articles = $this->conn->query("SELECT id, title, slug, category_id FROM articles ORDER BY title ASC")->fetchAll();

        // 3. Build structure
        $menu = [];
        foreach ($categories as $cat) {
            $menu[$cat['id']] = [
                'id' => $cat['id'],
                'name' => $cat['name'],
                'slug' => $cat['slug'],
                'articles' => []
            ];
        }

        foreach ($articles as $art) {
            if (isset($menu[$art['category_id']])) {
                $menu[$art['category_id']]['articles'][] = [
                    'id' => $art['id'],
                    'title' => $art['title'],
                    'slug' => $art['slug']
                ];
            }
        }

        return array_values($menu); // Return indexed array
    }

    public function findById(int $id): ?array
    {
        $stmt = $this->conn->prepare("SELECT * FROM articles WHERE id = :id");
        $stmt->execute(['id' => $id]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result ?: null;
    }

    public function exists(string $slug, ?int $excludeId = null): bool
    {
        $sql = "SELECT COUNT(*) FROM articles WHERE slug = :slug";
        $params = ['slug' => $slug];

        if ($excludeId) {
            $sql .= " AND id != :id";
            $params['id'] = $excludeId;
        }

        $stmt = $this->conn->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchColumn() > 0;
    }

    public function create(int $categoryId, string $title, string $slug, string $content, ?int $authorId): int
    {
        $stmt = $this->conn->prepare("
            INSERT INTO articles (category_id, title, slug, content, author_id) 
            VALUES (:category_id, :title, :slug, :content, :author_id)
        ");
        $stmt->execute([
            'category_id' => $categoryId,
            'title' => $title,
            'slug' => $slug,
            'content' => $content,
            'author_id' => $authorId
        ]);
        return (int) $this->conn->lastInsertId();
    }

    public function update(int $id, int $categoryId, string $title, string $slug, string $content): bool
    {
        $stmt = $this->conn->prepare("
            UPDATE articles 
            SET category_id = :category_id, title = :title, slug = :slug, content = :content 
            WHERE id = :id
        ");
        return $stmt->execute([
            'id' => $id,
            'category_id' => $categoryId,
            'title' => $title,
            'slug' => $slug,
            'content' => $content
        ]);
    }

    public function delete(int $id): bool
    {
        $stmt = $this->conn->prepare("DELETE FROM articles WHERE id = :id");
        return $stmt->execute(['id' => $id]);
    }
}
