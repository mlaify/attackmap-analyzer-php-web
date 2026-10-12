<?php

namespace App\Controller;

use Symfony\Component\Routing\Attribute\Route;

#[Route('/blog')]
final class BlogController
{
    #[Route('/', name: 'blog_index', methods: ['GET'])]
    public function index(): array
    {
        return [];
    }

    // Not a route: #[IsGranted('ROLE_EDITOR')] in a comment.
    #[Route(path: '/{slug}', name: 'blog_post', methods: 'GET')]
    public function show(string $slug): array
    {
        return [];
    }

    #[Route('/comment', name: 'delete_me_not', methods: ['POST'])]
    public function comment(): array
    {
        return [];
    }
}
