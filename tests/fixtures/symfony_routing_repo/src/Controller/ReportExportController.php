<?php

namespace App\Controller;

use Symfony\Component\Routing\Attribute\Route;

// Invokable: the class-level route is the route.
#[Route('/reports/export', methods: ['POST'])]
final class ReportExportController
{
    public function __invoke(): array
    {
        return [];
    }
}
