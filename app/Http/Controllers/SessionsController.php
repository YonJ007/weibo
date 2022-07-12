<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class SessionsController extends Controller
{
    public function create()
    {
        return view('sessions.create');
    }

    public function store(Request $request)
    {
        $credentials = $this->validate($request, [
            'email' => 'required|email|max:255',
            'password' => 'required'
        ]);
        if(Auth::attempt(['email'=>$request->email,'password'=>$request->password])){
            session()->flash('success','欢迎回来！');
            return redirect()->route('users.show',[Auth::user()]);
        }else{
            session()->flash('danger','用户名或密码不正确');
            return redirect()->back()->withInput();
        }
    }

}
