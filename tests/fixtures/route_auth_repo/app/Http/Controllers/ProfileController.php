<?php

namespace App\Http\Controllers;

class ProfileController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth')->except(['show']);
    }

    public function update()
    {
        return response()->noContent();
    }

    public function show($id)
    {
        return ['id' => $id];
    }
}
