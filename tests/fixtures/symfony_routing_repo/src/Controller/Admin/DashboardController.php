<?php

namespace App\Controller\Admin;

use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/admin', methods: ['GET']), IsGranted('ROLE_ADMIN')]
class DashboardController
{
    #[Route('/stats')]
    public function stats(): array
    {
        return [];
    }

    #[Route('/purge', methods: ['POST'])]
    public function purge(): array
    {
        return [];
    }
}
