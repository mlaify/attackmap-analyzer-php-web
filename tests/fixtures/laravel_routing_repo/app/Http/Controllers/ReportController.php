<?php

namespace App\Http\Controllers;

class ReportController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth')->only(['archive']);
    }
}
