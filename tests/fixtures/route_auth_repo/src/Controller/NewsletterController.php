<?php

namespace App\Controller;

use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class NewsletterController
{
    #[IsGranted('PUBLIC_ACCESS')]
    #[Route('/newsletter/subscribe', methods: ['POST'])]
    public function subscribe(): array
    {
        return [];
    }

    #[Route('/reports/export', methods: ['POST'])]
    public function export(): array
    {
        return [];
    }

    #[Route('/catalog/import', methods: ['POST'])]
    public function import(): array
    {
        return [];
    }
}
