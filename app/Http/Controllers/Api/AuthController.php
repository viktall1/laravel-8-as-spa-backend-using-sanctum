<?php

// namespace App\Http\Controllers;
namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function users()
    {
        // return RB::success();

        return User::all();

    }
    /**
     * Register a new user.
     *
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request)
    {

        $rules = [
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users|max:255',
            'password' => 'required|string|confirmed|min:8',
        ];
        $messages = [];
        $custom_attribute = [];

        $validator = Validator::make($request->all(), $rules, $messages, $custom_attribute);
        if ($validator->fails()) {
            $data = [$validator->messages()];
            return json_response()->error($data);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        $token = $user->createToken('myapptoken')->plainTextToken;
        $data = [
            'user' => $user,
            'token' => $token,
        ];
        return response()->json($data, 200);
    }
    /**
     * Register a new user.
     *
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request)
    {

        $rules = [
            'email' => 'required|email|max:255',
            'password' => 'required|string|min:8',
        ];
        $messages = [
            //'body.min' => 'We need to get a body up to 20 characters!',
        ];
        $custom_attribute = [
            //    'newsletter_email' => 'email',
        ];

        $validator = Validator::make($request->all(), $rules, $messages, $custom_attribute);
        if ($validator->fails()) {
            $data = [$validator->messages()];
            return json_response()->error($data);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            $data = [
                'error' => 'The provided credentials are incorrect.',
            ];
            return json_response()->error($data);
        }

        $token = $user->createToken('myapptoken')->plainTextToken;
        $data = [
            'user' => $user,
            'token' => $token,
        ];
        return response()->json($data);

    }
    /**
     * Forgot user login.
     *
     * @return \Illuminate\Http\Response
     */
    public function forgot_password(Request $request)
    {

        $rules = [
            'email' => 'required|email|max:255',
        ];
        $messages = [
            //'body.min' => 'We need to get a body up to 20 characters!',
        ];
        $custom_attribute = [
            //    'newsletter_email' => 'email',
        ];

        $validator = Validator::make($request->all(), $rules, $messages, $custom_attribute);
        if ($validator->fails()) {
            $data = [$validator->messages()];
            return json_response()->error($data);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user) {

            $data = [
                'error' => 'The provided email does not exist.',
            ];
            return json_response()->error($data);

        }

        $status = Password::sendResetLink(
            $request->only('email')
        );

        if ($status === Password::RESET_LINK_SENT) {
            // $data = [
            //     'message' => __($status),
            // ];
            return response()->json(['message' => __($status)]);
        } else {
            // $data = [
            //     'error_title' => __($status),
            // ];
            return json_response()->error(['error' => __($status)]);
        }

    }

    /**
     * Forgot user login.
     *
     * @return \Illuminate\Http\Response
     */
    public function reset_password(Request $request)
    {

        $rules = [
            'email' => 'required|email|max:255',
            'token' => 'required',
            'password' => 'required|min:8|confirmed',
        ];
        $messages = [
            //'body.min' => 'We need to get a body up to 20 characters!',
        ];
        $custom_attribute = [
            //    'newsletter_email' => 'email',
        ];

        $validator = Validator::make($request->all(), $rules, $messages, $custom_attribute);
        if ($validator->fails()) {
            $data = [$validator->messages()];
            return json_response()->error($data);
        }

        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function ($user, $password) {
                $user->forceFill([
                    'password' => Hash::make($password),
                ])->setRememberToken(Str::random(60));

                $user->save();

                // event(new PasswordReset($user));
            }
        );

        if ($status === Password::PASSWORD_RESET) {
        
            return response()->json(['message' => __($status)]);
        } else {
            
            return json_response()->error(['error' => __($status)]);
        }
    }

    /**
     * Logout a user.
     *
     * @return \Illuminate\Http\Response
     */
    public function logout(Request $request)
    {
      //  auth()->user()->tokens()->delete();

       return response()->json(
           [ 'message' => 'logged out'],
        );

    }

}
