<?php

namespace App\Controllers\Admin;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use finfo;
use Exception;

class UploadController
{
    public function upload(Request $request, Response $response): Response
    {
        $uploadedFiles = $request->getUploadedFiles();
        if (empty($uploadedFiles['image'])) {
            throw new Exception("No image uploaded", 400);
        }

        $uploadedFile = $uploadedFiles['image'];
        if ($uploadedFile->getError() !== UPLOAD_ERR_OK) {
            throw new Exception("File upload failed", 500);
        }

        $filename = $uploadedFile->getClientFilename();
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        // Validation
        $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'];
        $allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'];
        
        if (!in_array($extension, $allowedExtensions)) {
             throw new Exception("Invalid file extension. Allowed: " . implode(', ', $allowedExtensions), 400);
        }

        // Mime Type Check
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->buffer($uploadedFile->getStream()->getContents());
        
        // Reset stream
        $uploadedFile->getStream()->rewind();

        if (!in_array($mimeType, $allowedMimeTypes)) {
             // Exception for SVG which can be finicky
            if ($extension === 'svg' && str_contains($mimeType, 'xml')) {
                // Allow XML mime types for SVG
            } else {
                 throw new Exception("Invalid file type: $mimeType", 400);
            }
        }

        // Size Check (5MB)
        if ($uploadedFile->getSize() > 5 * 1024 * 1024) {
             throw new Exception("File too large. Max 5MB.", 400);
        }

        // Generate Unique Name
        $basename = bin2hex(random_bytes(8));
        $newFilename = sprintf('%s.%s', $basename, $extension);
        
        // Target Directory (relative to index.php, but this runs in Controller context, 
        // need to be careful with paths if we move execution context, but __DIR__ changes)
        // Actually, we pass the APP_ROOT via Environment OR use relative path from entry point.
        // For Valid Logic, let used fixed relative path from public_html/api/index.php 
        // We can inject the Upload Directory path if we want to be fancy, but keep it simple.
        
        // HARDCODE: Assuming this runs from public_html/api/index.php
        $uploadsDir = __DIR__ . '/../../../../public_html/uploads';
        
        if (!is_dir($uploadsDir)) {
            mkdir($uploadsDir, 0755, true);
        }

        $uploadedFile->moveTo($uploadsDir . DIRECTORY_SEPARATOR . $newFilename);

        // Build Public URL
        $scheme = $request->getUri()->getScheme();
        $host = $request->getUri()->getHost();
        $port = $request->getUri()->getPort();
        
        $baseUrl = $scheme . '://' . $host;
        if ($port && $port !== 80 && $port !== 443) {
            $baseUrl .= ':' . $port;
        }

        $url = $baseUrl . '/uploads/' . $newFilename;

        $response->getBody()->write(json_encode([
            "status" => "success", 
            "url" => $url,
            "filename" => $newFilename
        ]));
        return $response->withStatus(201)->withHeader('Content-Type', 'application/json');
    }
}
