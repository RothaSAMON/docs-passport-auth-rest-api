<?php
namespace App\Services;

use App\Repository\AuthRepository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\Client;

class AuthService
{

    protected $authRepository;

    /**
     * Create a new class instance.
     */
    public function __construct(AuthRepository $authRepository)
    {
        $this->authRepository = $authRepository;
    }

    /**
     * Function: authRegister
     * @param $request
     * @return $response
     */
    public function authRegister($request)
    {
        $request             = $request->all();
        $request['password'] = Hash::make($request['password']);

        # Register User
        return $this->authRepository->registerUser($request);
    }

    /**
     * Function: authRegister
     * @param $request
     * @return $response
     */
    public function userLogin($request)
    {
        if (!Auth::attempt(['email' => $request['email'], 'password' => $request['password']])) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        // Get the password grant client
        $client = Client::where('password_client', true)->first();
        if (!$client) {
            return response()->json(['error' => 'No password grant client found'], 500);
        }

        // Manually create a request to /oauth/token
        $tokenRequest = Request::create('/oauth/token', 'POST', [
            'grant_type'    => 'password',
            'client_id'     => $client->id,
            'client_secret' => $client->secret,
            'username'      => $request->email,
            'password'      => $request->password,
            'scope'         => '',
        ]);

        // Handle the request internally
        $response = app()->handle($tokenRequest);
        return response()->json(json_decode($response->getContent(), true));
    }
    // public function userLogin($request)
    // {
    //     if (! (Auth::attempt(['email' => $request['email'], 'password' => $request['password']]))) {
    //         return false;
    //     }

    //     $url = env('APP_URL') . '/oauth/token';

    //     $response = Http::asForm()->post($url, [
    //         'grant_type'    => 'password',
    //         'client_id'     => env('PASSPORT_PERSONAL_ACCESS_CLIENT_ID'),
    //         'client_secret' => env('PASSPORT_PERSONAL_ACCESS_CLIENT_SECRET'),
    //         'username'      => $request->email,
    //         'password'      => $request->password,
    //         'scope'         => '',
    //     ]);

    //     dd('hiii');

    //     // dd($response->json());

    //     $authUser = Auth::user();
    //     $token    = $authUser->createToken('token')->accessToken;

    //     return [
    //         'email' => $authUser->email,
    //         'token' => $token,
    //     ];
    // }

    /**
     * Function: userProfile
     */
    public function userProfile()
    {
        return Auth::user();
    }

    /**
     * Function: userLogout
     * @return boolean
     */
    public function userLogout()
    {
        $authUser = Auth::user();
        if ($authUser) {
            $authUser->token()->revoke();
            return true;
        }
        return false;
    }

    /**
     * Function: getAuthUser
     */
    public function getAuthUser() {
        return Auth::user();
    }

    /**
     * Function: refreshToken
     */
    public function refreshToken($request)
    {
        $client = Client::where('password_client', true)->first();
        if (!$client) {
            return response()->json(['error' => 'No password grant client found'], 500);
        }

        // Manually create a request to /oauth/token
        $tokenRequest = Request::create('/oauth/token', 'POST', [
            'grant_type'    => 'refresh_token',
            'refresh_token' => $request->refresh_token,
            'client_id'     => $client->id,
            'client_secret' => $client->secret,
            'scope'         => '',
        ]);

        // Handle the request internally
        $response = app()->handle($tokenRequest);
        
        // return response()->json(json_decode($response->getContent(), true));
        $data = json_decode($response->getContent(), true);

        // Only the required fields
        return ([
            'token_type'   => $data['token_type'] ?? null,
            'expires_in'   => $data['expires_in'] ?? null,
            'access_token' => $data['access_token'] ?? null,
            'refresh_token'=> $data['refresh_token'] ?? null,
        ]);
    }

    // public function refreshToken($request)
    // {
    //     $response = Http::asForm()->post(url('oauth/token'), [
    //         'grant_type'    => 'refresh_token',
    //         'refresh_token' => $request->refresh_token,
    //         'client_id'     => env('PASSPORT_PERSONAL_ACCESS_CLIENT_ID'),
    //         'client_secret' => env('PASSPORT_PERSONAL_ACCESS_CLIENT_SECRET'),
    //         'scope'         => '',
    //     ]);

    //     dd($response->json());
    // }
}
