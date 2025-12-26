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
}
