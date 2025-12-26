<?php

namespace App\Controllers\Admin;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use App\Article;
use App\Category;
use Exception;

class ArticleController
{
    private Article $articleModel;
    private Category $categoryModel;

    public function __construct(Article $articleModel, Category $categoryModel)
    {
        $this->articleModel = $articleModel;
        $this->categoryModel = $categoryModel;
    }

    public function create(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        $categoryId = (int) ($data['category_id'] ?? 0);
        $title = trim($data['title'] ?? '');
        $slug = trim($data['slug'] ?? '');
        $content = trim($data['content'] ?? '');
        
        $token = $request->getAttribute('token');
        $authorId = $token['sub'] ?? null;

        if (empty($title) || empty($slug) || $categoryId <= 0) {
            throw new Exception("Title, Slug, and Category ID are required", 400);
        }

        $slug = strtolower($slug);
        if (!preg_match('/^[a-z0-9-]+$/', $slug)) {
            throw new Exception("Invalid slug format.", 400);
        }

        if (!$this->categoryModel->findById($categoryId)) {
            throw new Exception("Category not found", 404);
        }

        if ($this->articleModel->exists($slug)) {
            throw new Exception("An article with this slug already exists.", 409);
        }

        $id = $this->articleModel->create($categoryId, $title, $slug, $content, $authorId);

        $response->getBody()->write(json_encode(["status" => "success", "data" => ["id" => $id]]));
        return $response->withStatus(201)->withHeader('Content-Type', 'application/json');
    }

    public function update(Request $request, Response $response, array $args): Response
    {
        $id = (int) $args['id'];
        $data = $request->getParsedBody();
        $categoryId = (int) ($data['category_id'] ?? 0);
        $title = trim($data['title'] ?? '');
        $slug = trim($data['slug'] ?? '');
        $content = trim($data['content'] ?? '');

        if (empty($title) || empty($slug) || $categoryId <= 0) {
            throw new Exception("Title, Slug, and Category ID are required", 400);
        }

        $slug = strtolower($slug);
        if (!preg_match('/^[a-z0-9-]+$/', $slug)) {
            throw new Exception("Invalid slug format.", 400);
        }

        if ($this->articleModel->exists($slug, $id)) {
            throw new Exception("Slug is already in use by another article.", 409);
        }

        if (!$this->articleModel->findById($id)) {
            throw new Exception("Article not found", 404);
        }

         if (!$this->categoryModel->findById($categoryId)) {
            throw new Exception("Category not found", 404);
        }

        $this->articleModel->update($id, $categoryId, $title, $slug, $content);

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Article updated"]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function delete(Request $request, Response $response, array $args): Response
    {
        $id = (int) $args['id'];

        if (!$this->articleModel->findById($id)) {
            throw new Exception("Article not found", 404);
        }

        $this->articleModel->delete($id);

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Article deleted"]));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
