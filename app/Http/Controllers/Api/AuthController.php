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
        $messages = [
            //'body.min' => 'We need to get a body up to 20 characters!',
        ];
        $custom_attribute = [
            //    'newsletter_email' => 'email',
        ];

        $validator = Validator::make($request->all(), $rules, $messages, $custom_attribute);
        if ($validator->fails()) {
            // $data = [$validator->messages()];
            // return json_response()->error($data);


            $data = ['validator_errors' => $validator->messages()];
            return response()->json($data, 422);
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
            $data = [
                'error_title' => 'validation_error',
                'validator_errors' => $validator->messages(),
            ];
            return response()->json($data, 422);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            // throw ValidationException::withMessages([
            //     'error' => ['The provided credentials are incorrect.'],
            //     'error_type' => ['incorrect_credentiials_error'],
            // ]);
            $data = [
                'error_title' => 'incorrect_credentials',
                'message' => 'The provided credentials are incorrect.',
            ];

            return response()->json($data, 422);
        }

        $token = $user->createToken('myapptoken')->plainTextToken;
        $data = [
            'user' => $user,
            'token' => $token,
        ];
        return response()->json($data, 200);

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
            $data = [
                'error_title' => 'validation_error',
                'validator_errors' => $validator->messages(),
            ];
            return response()->json($data, 422);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user) {

            $data = [
                'error_title' => 'incorrect_credentials',
                'message' => 'The provided email does not exist.',
            ];

            return response()->json($data, 422);
        }

        $status = Password::sendResetLink(
            $request->only('email')
        );

        if ($status === Password::RESET_LINK_SENT) {
            $data = [
                'message' => __($status),
            ];
            return response()->json(['message' => __($status)], 200);
        } else {
            $data = [
                'error_title' => __($status),
            ];
            return response()->json(['message' => __($status)], 500);
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
            $data = [
                'error_title' => 'validation_error',
                'validator_errors' => $validator->messages(),
            ];
            return response()->json($data, 422);
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
            $data = [
                'message' => __($status),
            ];
            return response()->json(['message' => __($status)], 200);
        } else {
            $data = [
                'error_title' => __($status),
            ];
            return response()->json(['message' => __($status)], 500);
        }
        ////

    }

    /**
     * Logout a user.
     *
     * @return \Illuminate\Http\Response
     */
    public function logout(Request $request)
    {
        auth()->user()->tokens()->delete();

        return [
            'message' => 'logged out',
        ];

    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {

    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        //
    }
}
