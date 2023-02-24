import rest, { RestOptions } from "@halliday/rest";

export const config = {
    baseUrl: "/",
}

//

export type TokenRequest = {
    grant_type: "authorization_code" | "refresh_token" | "password";
    code?: string;
    refresh_token?: string;
    username?: string;
    password?: string;
    scope?: string;
}

export type TokenResponse = {
    access_token: string,
    token_type: string,
    expires_in: number,
    refresh_token?: string,
    scope?: string,
    id_token?: string,
}

export function token(req: TokenRequest, opts?: RestOptions): Promise<TokenResponse> {
    return rest("POST", config.baseUrl + "token", req, { ...opts, contentType: "application/x-www-form-urlencoded" });
}

//

export type User = {
    id: string,
    createdAt: Date,

    username?: string,
    usernameVerified?: boolean,

    profile?: string,
    picture?: string,
    website?: string,

    email?: string,
    emailVerified?: boolean,

    gender?: string,
    birthdate?: string,
    zoneinfo?: string,
    locale?: string,

    phoneNumber?: string,
    phoneNumberVerified?: boolean,

    methods?: SocialProvider[],

    suspended?: boolean,

    scopes?: string[],

    password?: string,

    updatedAt?: Date,
}

export type NewUser = Omit<User, "id" | "createdAt" | "updatedAt" | "profile" | "picture" | "website">;


// requires authentication
export function userinfo(opts?: RestOptions): Promise<User> {
    return rest("GET", config.baseUrl + "userinfo", null, opts);
}

//

export type LoginRequest = {
    username: string;
    password: string;
    scope?: string;
    nonce?: string;
}

export type LoginResponse = TokenResponse;

export function login(username: string, password: string, opts?: RestOptions): Promise<LoginResponse> {
    return rest("POST", config.baseUrl + "login", { username, password }, opts);
}

//

export function logout(refreshToken: string, opts?: RestOptions): Promise<void> {
    return rest("POST", config.baseUrl + "logout", { refreshToken }, opts);
}

//

export type RegistrationResponse = LoginResponse;

export function register(user: NewUser, password: string, redirectUri: string, opts?: RestOptions): Promise<RegistrationResponse> {
    return rest("POST", config.baseUrl + "register", { ...user, password, redirectUri }, opts);
}

//

export function completeRegistration(registrationToken: string, redirectUri?: string, opts?: RestOptions): Promise<void> {
    return rest("POST", config.baseUrl + "complete-registration", { registrationToken, redirectUri }, opts);
}

//

export function instructPasswordReset(email: string, redirectUri?: string, opts?: RestOptions): Promise<void> {
    return rest("POST", config.baseUrl + "instruct-password-reset", { email, redirectUri }, opts);
}

//

export function resetPassword(resetPasswordToken: string, password: string, redirectUri?: string, opts?: RestOptions): Promise<void> {
    return rest("POST", config.baseUrl + "reset-password", { resetPasswordToken, password, redirectUri }, opts);
}

//

export function instructEmailChange(email: string, redirectUri?: string, opts?: RestOptions): Promise<void> {
    return rest("POST", config.baseUrl + "instruct-email-change", { email, redirectUri }, opts);
}

//

export function changeEmail(changeEmailToken: string, redirectUri?: string, opts?: RestOptions): Promise<void> {
    return rest("POST", config.baseUrl + "change-email", { changeEmailToken, redirectUri }, opts);
}

//

export function socialLoginUri(iss: string, redirectUri?: string) {
    return config.baseUrl + `social-login?iss=${encodeURIComponent(iss)}${redirectUri ? `&redirect_uri=${encodeURIComponent(redirectUri)}` : ""}`;
}

export function socialLogin(iss: string, redirectUri?: string, opts?: RestOptions): Promise<{redirectUri: string}> {
    return rest("POST", config.baseUrl + "social-login", { iss, redirectUri }, opts);
}

//

export type AuthCodeResponse = {
    code: string,
    state?: string,
}

export type AuthTokenResponse = {
    access_token: string,
    refresh_token?: string,
    token_type: string,
    expires_in: number,
    scope?: string,
    id_token?: string,
    state?: string,
}

export type IdTokenResponse = {
    idToken: string,
    state?: string,
}

export type AuthResponse = AuthCodeResponse | AuthTokenResponse | IdTokenResponse;

export function exchangeSocialLogin(auth: AuthResponse, scope?: string, nonce?: string, redirectUri?: string, opts?: RestOptions): Promise<TokenResponse> {
    return rest("POST", config.baseUrl + "exchange-social-login", { auth, scope, nonce, redirectUri }, opts);
}

//

export type SocialProvider = {
    iss: string,
}

export function socialProviders(opts?: RestOptions): Promise<SocialProvider[]> {
    return rest("GET", config.baseUrl + "social-providers", null, opts);
}

//

export type UsersQuery = {
    all?: boolean,
    ids?: string[],
    email?: string,
    search?: string
}

export type GetUsersRequest = UsersQuery & {
    pageSize?: number,
    pageToken?: string,
}

export type GetUsersResponse = {
    users: User[],
    numFound?: number,
    numTotal?: number,
    nextPageToken?: string,
}

export function findUsers(q: UsersQuery, pageSize?: number, pageToken?: string, opts?: RestOptions): Promise<GetUsersResponse> {
    return rest("GET", config.baseUrl + "users", { ...q, pageSize, pageToken }, opts);
}

//

export type UserUpdate = {
    username?: string,
    usernameVerified?: boolean,

    email?: string,
    emailVerified?: boolean,

    gender?: string,
    birthdate?: string,
    zoneinfo?: string,
    locale?: string,
    phoneNumber?: string,
    phoneNumberVerified?: boolean,

    suspended?: boolean,

    newPassword?: string,
    oldPassword?: string,
}

export function updateUsers(sel: UsersQuery, update: UserUpdate, opts?: RestOptions): Promise<{numDeleted: number}> {
    return rest("PATCH", config.baseUrl + "users", { sel, update }, opts);
}

//

export function deleteUsers(sel: UsersQuery, opts?: RestOptions): Promise<{numUpdated: number}> {
    return rest("DELETE", config.baseUrl + "users", sel, opts);
}

//

export type SelfUserUpdate = Omit<UserUpdate, "preferred_username_verified" | "email_verified" | "phone_number_verified" | "suspended">;

export function updateUsersSelf(update: UserUpdate, opts?: RestOptions): Promise<void> {
    return rest("PATCH", config.baseUrl + "users/self", update, opts);
}

//

export function deleteUsersSelf(opts?: RestOptions): Promise<void> {
    return rest("DELETE", config.baseUrl + "users/self", null, opts);
}

//