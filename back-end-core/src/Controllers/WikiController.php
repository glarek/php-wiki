<?php

namespace App\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use App\Article;
use Exception;

class WikiController
{
    private Article $articleModel;

    public function __construct(Article $articleModel)
    {
        $this->articleModel = $articleModel;
    }

    public function getMenu(Request $request, Response $response): Response
    {
        $menu = $this->articleModel->getMenuStructure();
        $response->getBody()->write(json_encode(["status" => "success", "data" => $menu]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function getArticle(Request $request, Response $response, array $args): Response
    {
        $slug = $args['slug'];
        $article = $this->articleModel->getBySlug($slug);

        if (!$article) {
            $payload = json_encode(["status" => "error", "message" => "Article not found"]);
            $response->getBody()->write($payload);
            return $response->withStatus(404)->withHeader('Content-Type', 'application/json');
        }

        $response->getBody()->write(json_encode(["status" => "success", "data" => $article]));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
