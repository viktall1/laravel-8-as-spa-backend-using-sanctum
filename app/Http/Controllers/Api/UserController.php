<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        return User::paginate(15);
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */


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
        if (!User::where("id", "=", $id)->count() > 0) {
            return json_response()->error(['error' => 'record does not exist']);
        }

        return User::findOrFail($id);
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

        $rules = [
            'name' => 'required|string|max:255',
            'email' => 'required|email|max:255',
            'password' => 'required|min:8|confirmed',
        ];
        $messages = [
        ];
        $custom_attribute = [
        ];

        $validator = Validator::make($request->all(), $rules, $messages, $custom_attribute);
        if ($validator->fails()) {
            $data = [$validator->messages()];
            return json_response()->error($data);
        }

        if (!User::where("id", "=", $id)->count() > 0) {
            return json_response()->error(['error' => 'record does not exist']);
        }

        $user = User::find($id);

        $user->name = $request->name;
        // $user->email = $request->email;
        $user->password = $request->password;

        if ($user->save()) {
            return response()->json(['message' => 'record updated successfully']);
        } else {
            return json_response()->error(['error' => 'an error occured']);
        }

    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        if (!User::where("id", "=", $id)->count() > 0) {
            return json_response()->error(['error' => 'record does not exist']);
        }

        if (User::destroy($id)) {

            return response()->json(['message' => 'record successfully deleted']);
        } else {

            return json_response()->error(['error' => 'an error occured']);
        }

    }
}
