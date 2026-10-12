<?php

namespace App\Http\Controllers;

class PhotoController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth')->except(['index', 'show']);
    }
}
