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

export type Address = {
    formatted: string,
    street_address: string,
    locality: string,
    region: string,
    postal_code: string,
    country: string,
}

export type Userinfo = {
    sub: string,

    name?: string,
    given_name?: string,
    family_name?: string,
    middle_name?: string,
    nickname?: string,

    preferred_username?: string,
    preferred_username_verified?: boolean,

    profile?: string,
    picture?: string,
    website?: string,

    email?: string,
    email_verified?: boolean,

    gender?: string,
    birthdate?: string,
    zoneinfo?: string,
    locale?: string,
    phone_number?: string,
    phone_number_verified?: boolean,
    address?: Address,

    social_providers?: SocialProvider[],

    updated_at?: number,
}

export type User = Userinfo & {
    suspended?: boolean,
}

export type NewUser = Omit<Userinfo, "sub" | "created_at" | "preferred_username_verified" | "profile" | "picture" | "website" | "email_verified" | "social_providers" | "updated_at">;


// requires authentication
export function userinfo(opts?: RestOptions): Promise<Userinfo> {
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
    return rest("POST", config.baseUrl + "ident/login", { username, password }, opts);
}

//

export function logout(refreshToken: string, opts?: RestOptions): Promise<void> {
    return rest("POST", config.baseUrl + "ident/logout", { refreshToken }, opts);
}

//

export function register(user: NewUser, password: string, redirectUri: string, opts?: RestOptions): Promise<void> {
    return rest("POST", config.baseUrl + "ident/register", { ...user, password, redirectUri }, opts);
}

//

export function completeRegistration(registrationToken: string, redirectUri?: string, opts?: RestOptions): Promise<void> {
    return rest("POST", config.baseUrl + "ident/complete-registration", { registrationToken, redirectUri }, opts);
}

//

export function instructPasswordReset(email: string, redirectUri?: string, opts?: RestOptions): Promise<void> {
    return rest("POST", config.baseUrl + "ident/instruct-password-reset", { email, redirectUri }, opts);
}

//

export function resetPassword(resetPasswordToken: string, password: string, redirectUri?: string, opts?: RestOptions): Promise<void> {
    return rest("POST", config.baseUrl + "ident/reset-password", { resetPasswordToken, password, redirectUri }, opts);
}

//

export function instructEmailChange(email: string, redirectUri?: string, opts?: RestOptions): Promise<void> {
    return rest("POST", config.baseUrl + "ident/instruct-email-change", { email, redirectUri }, opts);
}

//

export function changeEmail(changeEmailToken: string, redirectUri?: string, opts?: RestOptions): Promise<void> {
    return rest("POST", config.baseUrl + "ident/change-email", { changeEmailToken, redirectUri }, opts);
}

//

export function socialLoginUri(iss: string, redirectUri?: string) {
    return config.baseUrl + `ident/social-login?iss=${encodeURIComponent(iss)}${redirectUri ? `&redirect_uri=${encodeURIComponent(redirectUri)}` : ""}`;
}

export function socialLogin(iss: string, redirectUri?: string, opts?: RestOptions): Promise<{redirectUri: string}> {
    return rest("POST", config.baseUrl + "ident/social-login", { iss, redirectUri }, opts);
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
    return rest("POST", config.baseUrl + "ident/exchange-social-login", { auth, scope, nonce, redirectUri }, opts);
}

//

export type SocialProvider = {
    iss: string,
}

export function socialProviders(opts?: RestOptions): Promise<SocialProvider[]> {
    return rest("GET", config.baseUrl + "ident/social-providers", null, opts);
}

//

export type Selection = {
    all?: boolean,
    ids?: string[],
    email?: string,
    search?: string
}

export type GetUsersRequest = Selection & {
    pageSize?: number,
    pageToken?: string,
}

export type GetUsersResponse = {
    users: User[],
    numFound?: number,
    numTotal?: number,
    nextPageToken?: string,
}

export function getUsers(sel: Selection, pageSize?: number, pageToken?: string, opts?: RestOptions): Promise<GetUsersResponse> {
    return rest("GET", config.baseUrl + "ident/users", { ...sel, pageSize, pageToken }, opts);
}

//

export type UserUpdate = {
    name?: string,
    given_name?: string,
    family_name?: string,
    middle_name?: string,
    nickname?: string,
    preferred_username?: string,
    preferred_username_verified?: boolean,

    email?: string,
    email_verified?: boolean,

    gender?: string,
    birthdat?: string,
    zoneinfo?: string,
    locale?: string,
    phone_number?: string,
    phone_number_verified?: boolean,
    address?: Address,

    suspended?: boolean,

    new_password?: string,
    old_password?: string,
}

export function updateUsers(sel: Selection, update: UserUpdate, opts?: RestOptions): Promise<{numDeleted: number}> {
    return rest("PATCH", config.baseUrl + "ident/users", { sel, update }, opts);
}

//

export function deleteUsers(sel: Selection, opts?: RestOptions): Promise<{numUpdated: number}> {
    return rest("DELETE", config.baseUrl + "ident/users", sel, opts);
}

//

export type SelfUserUpdate = Omit<UserUpdate, "preferred_username_verified" | "email_verified" | "phone_number_verified" | "suspended">;

export function updateUsersSelf(update: UserUpdate, opts?: RestOptions): Promise<void> {
    return rest("PATCH", config.baseUrl + "ident/users/self", update, opts);
}

//

export function deleteUsersSelf(opts?: RestOptions): Promise<void> {
    return rest("DELETE", config.baseUrl + "ident/users/self", null, opts);
}

//