<?php

namespace App\Controller;

use Symfony\Component\Routing\Attribute\Route;

class OrderController
{
    #[Route('/orders/{id}', methods: ['GET', 'DELETE'])]
    public function order(int $id): array
    {
        return ['id' => $id];
    }
}
