<?php

namespace App\Controllers\Admin;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use App\Category;
use Exception;

class CategoryController
{
    private Category $categoryModel;

    public function __construct(Category $categoryModel)
    {
        $this->categoryModel = $categoryModel;
    }

    public function create(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        $name = trim($data['name'] ?? '');
        $slug = trim($data['slug'] ?? '');
        $sortOrder = (int) ($data['sort_order'] ?? 0);

        if (empty($name) || empty($slug)) {
            throw new Exception("Name and Slug are required", 400);
        }

        $name = strip_tags($name);
        $slug = strtolower($slug);
        if (!preg_match('/^[a-z0-9-]+$/', $slug)) {
            throw new Exception("Invalid slug format. Use only lowercase letters, numbers, and hyphens.", 400);
        }

        if ($this->categoryModel->exists($slug)) {
            throw new Exception("A category with this slug already exists.", 409);
        }

        $id = $this->categoryModel->create($name, $slug, $sortOrder);

        $response->getBody()->write(json_encode(["status" => "success", "data" => ["id" => $id]]));
        return $response->withStatus(201)->withHeader('Content-Type', 'application/json');
    }

    public function update(Request $request, Response $response, array $args): Response
    {
        $id = (int) $args['id'];
        $data = $request->getParsedBody();
        $name = trim($data['name'] ?? '');
        $slug = trim($data['slug'] ?? '');
        $sortOrder = (int) ($data['sort_order'] ?? 0);

        if (empty($name) || empty($slug)) {
            throw new Exception("Name and Slug are required", 400);
        }

        $name = strip_tags($name);
        $slug = strtolower($slug);
        if (!preg_match('/^[a-z0-9-]+$/', $slug)) {
            throw new Exception("Invalid slug format.", 400);
        }

        if ($this->categoryModel->exists($slug, $id)) {
            throw new Exception("Slug is already in use by another category.", 409);
        }

        if (!$this->categoryModel->findById($id)) {
            throw new Exception("Category not found", 404);
        }

        $this->categoryModel->update($id, $name, $slug, $sortOrder);

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Category updated"]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function delete(Request $request, Response $response, array $args): Response
    {
        $id = (int) $args['id'];

        if (!$this->categoryModel->findById($id)) {
            throw new Exception("Category not found", 404);
        }

        $this->categoryModel->delete($id);

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Category deleted"]));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
