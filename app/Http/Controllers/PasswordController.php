<?php

namespace App\Http\Controllers;

use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;

class PasswordController extends Controller
{

    public function __construct()
    {
        //限流 10分钟3次
        $this->middleware('throttle:3,10',[
            'only'=>['sendResetLinkEmail']
        ]);
    }

    public function showLinkRequestForm()
    {
        return view('users.pwd');
    }

    public function sendResetLinkEmail(Request $request)
    {
        //1 验证邮箱
        $request->validate(['email'=>'required|email']);
        $email = $request->email;
        //2 获取对应用户
        $user = User::where('email',$email)->first();
        //3 判断用户是否存在
        if (is_null($user)) {
            session()->flash('danger','邮箱未注册');
            return redirect()->back()->withInput();
        }
        //4 生成token
        $token = hash_hmac('sha256',Str::random(40),config('app.key'));

        //5 入库
        DB::table('password_resets')->updateOrInsert(['email'=>$email],['email'=>$email,'token'=>Hash::make($token),'created_at'=>new Carbon]);

        //6 将token链接发给用户
        Mail::send('users.reset_link',compact('token'),function($message) use ($email){
            $message->to($email)->subject('忘记密码');
        });

        session()->flash('success','重置邮件发送成功，请查收');
        return redirect()->back();
    }

    public function showResetForm(Request $request)
    {
        $token = $request->route()->parameter('token');
        return view('users.reset_pwd', compact('token'));
    }

    public function reset(Request $request)
    {
        //验证数据
        $request->validate([
            'token'=>'required',
            'email'=>'required|email',
            'password'=>'required|confirmed|min:8'
        ]);
        $email = $request->email;
        $token = $request->token;
        $expires = 60*60;

        //验证邮箱
        $user = User::where('email',$email)->first();

        if(is_null($user)){
            session()->flash('danger','邮箱未注册');
            return redirect()->back()->withInput();
        }
        //验证链接
        $record = (array)DB::table('password_resets')->where('email',$email)->first();

        if($record){
            //链接失效
            if(Carbon::parse($record['created_at'])->addSeconds($expires)->isPast()){
                session()->flash('danger','链接已过期，请重新尝试');
                return redirect()->back();
            }

            //验证令牌
            if(!Hash::check($token,$record['token'])){
                session()->flash('danger','令牌错误');
                return redirect()->back();
            }


            //一切正常，更新用户密码
            $user->update(['password'=>bcrypt($request->password)]);
            //重置完密码让用户重新登录增加印象
            Auth::logout();
            //重定向到登录页
            session()->flash('success','密码重置成功，请使用新尼玛登录');

            return redirect()->route('login');
        }

        session()->flash('danger','无效链接');
        return redirect()->back();
    }
}
