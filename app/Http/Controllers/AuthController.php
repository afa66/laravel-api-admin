<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Transformers\UserTransformer;

class AuthController extends Controller
{
    /**
     * Get a JWT token via given credentials.
     *
     * @param  \Illuminate\Http\Request $request
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        // 验证规则，由于业务需求，这里我更改了一下登录的用户名，使用手机号码登录
        $rules = [
            'mobile'   => [
                'required',
                'exists:users',
            ],
            'password' => 'required|string|min:6|max:20',
         ];

        // 验证参数，如果验证失败，则会抛出 ValidationException 的异常
        $params = $this->validate($request, $rules);

       // 使用 Auth 登录用户，如果登录成功，则返回 201 的 code 和 token，如果登录失败则返回
        return ($token = Auth::guard('api')->attempt($params))
            ? response(['token' => 'bearer ' . $token], 201)
            : response(['error' => '账号或密码错误'], 400);
    }

    /**
     * 处理用户登出逻辑
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        Auth::guard('api')->logout();

        return response(['message' => '退出成功']);
    }

    public function register(Request $request)
    {
        try {
            // 规则
            $rules = [
                'name' => 'required|max:10',
                'email' => 'required|email',
                'password' => 'required'
            ];

            // 自定义消息
            $messages = [
                'name.required' => '请输入用户名',
                'name.max' => '用户名的长度不能超过10个字符',
                'email.required' => '请输入邮箱',
                'email.email' => '请输入正确的邮箱格式',
                'password.required' => '请输入密码'
            ];

            $this->validate($request, $rules, $messages);

            $name = $request->input('name');
            $email = $request->input('email');
            $password = $request->input('password');

            $user = new User();
            $user->name = $name;
            $user->email = $email;
            $user->password = bcrypt($password);
            $user->save();

            \Auth::login($user); // 注册的用户让其进行登陆状态

            return redirect()->route('user.info');
        } catch (ValidationException $validationException) {
            $message = $validationException->validator->getMessageBag()->first();
            return $message;
        }
    }
}
