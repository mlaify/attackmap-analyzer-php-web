<?php

namespace App\Controller;

use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[IsGranted('ROLE_USER')]
final class AccountController
{
    #[Route('/account/email', methods: ['POST'])]
    public function changeEmail(): array
    {
        return [];
    }

    // Symfony checks class and method attributes cumulatively, so this
    // PUBLIC_ACCESS does not lift the class-level ROLE_USER requirement.
    #[Route('/account/avatar', methods: ['PUT'])]
    #[IsGranted('PUBLIC_ACCESS')]
    public function avatar(): array
    {
        return [];
    }
}
