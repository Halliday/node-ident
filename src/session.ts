import { Fetcher } from "@halliday/rest";
import * as api from "./api";
import { stripHashParams, stripParams, stripSearchParams } from "./tools";

export const nearlyExpiredThreshold = 30 * 1000; // 1 minute
export const defaultKey = "session";

export type Userinfo = api.Userinfo;
export type User = api.User;
export type UserUpdate = api.UserUpdate;
export type NewUser = api.NewUser;

const accessTokenSubjectPrefix = "user|";

export class Session {
    private pendingRefresh: Promise<void> | null = null;
    public userinfo: Userinfo;

    constructor(
        readonly key: string,
        public accessToken: string,
        public refreshToken: string,
        public scopes: string[],
        public issuedAt: Date,
        public expiresAt: Date,
        public idToken: string,
    ) {
        this.fetch = this.fetch.bind(this);
        this.userinfo = parseToken(idToken);
    }

    get expired() {
        return new Date() > this.expiresAt;
    }

    get nearlyExpired() {
        return new Date().getTime() + nearlyExpiredThreshold > this.expiresAt.getTime();
    }

    // Session subject = User ID
    get sub() {
        const token = parseToken(this.accessToken) as AccessTokenClaims;
        return token.sub.slice(accessTokenSubjectPrefix.length);
    }

    async refresh(scope?: string): Promise<void> {
        if (this.pendingRefresh)
            return this.pendingRefresh;
        this.pendingRefresh = (async (): Promise<void> => {
            const req: api.TokenRequest = {
                grant_type: "refresh_token",
                refresh_token: this.refreshToken,
            };
            if (scope !== undefined)
                req.scope = scope;
            
            const resp = await api.token(req);

            this.accessToken = resp.access_token;
            this.refreshToken = resp.refresh_token ?? this.refreshToken;
            this.scopes = resp.scope === undefined ? this.scopes : (resp.scope === "" ? [] : resp.scope.split(" "));
            this.issuedAt = new Date();
            this.expiresAt = new Date(this.issuedAt.getTime() + resp.expires_in * 1000);
            this.idToken = resp.id_token || this.idToken;
            this.userinfo = parseToken(this.idToken);
            this.store();
        })();
        this.pendingRefresh.finally(() => {
            this.pendingRefresh = null
        });
        return this.pendingRefresh;
    }

    store() {
        const p = new URLSearchParams();
        p.set("access_token", this.accessToken);
        p.set("refresh_token", this.refreshToken);
        p.set("issued_at", Math.floor(this.issuedAt.getTime() / 1000).toString());
        p.set("expires_at", Math.floor(this.expiresAt.getTime() / 1000).toString());
        p.set("scope", this.scopes.join(" "));
        p.set("id_token", this.idToken);
        localStorage.setItem(this.key, p.toString());
    }

    async fetch(req: Request, fetcher: Fetcher = globalThis.fetch) {
        if (this.nearlyExpired) await this.refresh();
        req.headers.set("Authorization", `Bearer ${this.accessToken}`);
        return fetcher(req);
    }

    async updateSelf(u: UserUpdate) {
        await api.updateUsersSelf(u, { fetcher: this.fetch });
        this.userinfo = { ...this.userinfo, ...u };
        this.idToken = createToken(this.userinfo);
        this.store();
    }

    deleteSelf() {
        return api.deleteUsersSelf({ fetcher: this.fetch });
    }

    async fetchUserinfo() {
        const userinfo = await api.userinfo({ fetcher: this.fetch });
        this.idToken = createToken(userinfo);
        this.store();
    }

    logout() {
        this.delete();
        return api.logout(this.refreshToken);
    }

    delete() {
        deleteSession(this.key);
    }

    instructEmailChange(email: string, redirectUri = document.location.href): Promise<void> {
        return api.instructEmailChange(email, redirectUri, { fetcher: this.fetch });
    }
}

export function deleteSession(key = defaultKey) {
    localStorage.removeItem(key);
}


type AccessTokenClaims = {
    sub: string,
    scope: string
}

type ChangeEmailTokenClaims = {
    aud: "_change_email"
    sub: string,
    email: string
}

type PasswordResetTokenClaims = {
    aud: "_reset_password"
    sub: string,
    email: string
}

type RegistrationTokenClaims = {
    aud: "_complete_registration"
    sub: string,
    email: string
}

//

let emailHint: string | null = null;
let token: string | null = null;

export type OAuth2ErrorStatus = "invalid_request" | "unauthorized_client" | "access_denied" | "unsupported_response_type" | "invalid_scope" | "server_error" | "temporarily_unavailable";

export type Status =
    "no-session" |
    "login" |
    "refreshed" | "revoked" | "loaded" |
    "email-confirmed" | "email-confirmation-failed" | "login-for-email-confirmation-required" |
    "password-reset-required" |
    "registration-completed" | "registration-failed" | "login-for-registration-required" |
    "social-login-exchanged" | "social-login-failed" |
    "unknown-token" |
    "invalid-subject" |
    `oauth2-${OAuth2ErrorStatus}`

export async function reviveSession(key = defaultKey): Promise<[sess: Session | null, status: Status]> {

    const storage = localStorage.getItem(key);
    if (!storage) return [null, "no-session"];

    const params = new URLSearchParams(storage);
    const accessToken = params.get("access_token")!;
    const refreshToken = params.get("refresh_token")!;
    const scope = params.get("scope")!;
    const scopes = scope === "" ? [] : scope.split(" ");
    const expiresAt = new Date(parseInt(params.get("expires_at")!) * 1000);
    const issuedAt = new Date(parseInt(params.get("issued_at")!) * 1000);
    const idToken = params.get("id_token")!;
    const sess = new Session(key, accessToken, refreshToken, scopes, issuedAt, expiresAt, idToken);

    if (sess.nearlyExpired) {
        try {
            await sess.refresh();
            return [sess, "refreshed"];
        } catch (err) {
            console.warn("The session could not be refreshed. The token loaded from local storage might be expired or was revoked.");
            localStorage.removeItem(key);
            return [null, "revoked"];
        }
    }
    try {
        await sess.fetchUserinfo();
    } catch (err) {
        localStorage.removeItem(key);
        return [null, "revoked"];
    }

    return [sess, "loaded"];
}

export async function loadSession(key = defaultKey): Promise<[sess: Session | null, status: Status]> {
    // 1 - check for a session in local storage
    let [sess, status] = await reviveSession(key); 

    // 2 - check for a token in the URL that might require some action
    const hash = new URLSearchParams(location.hash.slice(1));
    token = hash.get("token");
    if (token) {
        stripHashParams("token");
        status = await consumeToken(sess, token);
        if (status === "invalid-subject") {
            try {
                await sess!.logout();
            } catch (err) {
                // log error but discard anyways
                console.warn("The old session could not be logged out:", err);
            }
            sess = null;
            status = await consumeToken(null, token);
        }
        switch (status) {
            case "email-confirmed":
            case "email-confirmation-failed":
            case "registration-completed":
            case "registration-failed":
            case "unknown-token":
                token = null;
        }
    }


    // 3 - check for an code or access_token in the URL, as returned by an OAuth2 authorization server (e.g. a social login provider)
    const search = new URLSearchParams(window.location.search);

    // response_type=code
    // see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2
    const code = search.get("code") ?? hash.get("code") ?? undefined;
    // response_type=token
    // see https://www.rfc-editor.org/rfc/rfc6749#section-4.2.2
    const access_token = search.get("access_token") ?? hash.get("access_token") ?? undefined;
    const token_type = search.get("token_type") ?? hash.get("token_type") ?? undefined;
    const expires_in = search.get("expires_in") ?? hash.get("expires_in") ?? undefined;
    const scope = search.get("scope") ?? hash.get("scope") ?? undefined;
    const id_token = search.get("id_token") ?? hash.get("id_token") ?? undefined;

    const state = search.get("state") ?? hash.get("state") ?? undefined;

    if (code || access_token || id_token) {
        stripParams("code", "access_token", "token_type", "expires_in", "scope", "id_token", "state");
        location.hash = "";

        let resp: api.TokenResponse | undefined;
        try {
            resp = await api.exchangeSocialLogin({ code, access_token, token_type, expires_in, scope, id_token, state } as api.AuthResponse);
            status = "social-login-exchanged";
        } catch (err) {
            console.warn("The social login could not be completed. The token loaded from the URL is invalid or has expired.");
            status = "social-login-failed";
        }
        if (resp) {
            sess = sessionFromTokenResponse(key, resp);
            sess.store();
        }
    }

    const error = search.get("error") ?? hash.get("error") ?? undefined;
    if (error) {
        const errorDescription = search.get("error_description") ?? hash.get("error_description") ?? undefined;
        const errorUri = search.get("error_uri") ?? hash.get("error_uri") ?? undefined;
        stripParams("error", "error_description", "error_uri", "state");
        console.warn("OAuth2 error:", error, errorDescription, errorUri);
        status = `oauth2-${error as OAuth2ErrorStatus}`;
    }

    return [sess, status];
}

async function consumeToken(sess: Session | null, token: string): Promise<Status> {
    const redirectUri = new URLSearchParams(location.hash.slice(1)).get("redirect_uri") || undefined;
    const claims = parseToken(token!) as ChangeEmailTokenClaims | PasswordResetTokenClaims | RegistrationTokenClaims;
    if (sess && sess.sub !== claims.sub) {
        return "invalid-subject";
    }

    switch (claims.aud) {
        case "_change_email":
            if (sess) {
                const email = claims.email;
                try {
                    await api.changeEmail(token!, redirectUri, {fetcher: sess.fetch});

                    sess.userinfo = { ...sess.userinfo, email, email_verified: true };
                    sess.idToken = createToken(sess.userinfo);
                    sess.store();

                    return "email-confirmed";
                } catch (err) {
                    console.warn("The email change could not be completed. The token loaded from the URL is invalid or has expired.");
                    return "email-confirmation-failed";
                }
            } else {
                emailHint = claims.email;
                return "login-for-email-confirmation-required";
            }

        case "_reset_password":

            emailHint = claims.email;
            return "password-reset-required";

        case "_complete_registration":

        if (sess) {
                try {
                    await api.completeRegistration(token!, redirectUri, {fetcher: sess.fetch});
                    await sess.refresh();

                    sess.userinfo = { ...sess.userinfo, email_verified: true };
                    sess.idToken = createToken(sess.userinfo);
                    sess.store();

                    return "registration-completed";
                } catch (err) {
                    console.warn("The registration could not be completed. The token loaded from the URL is invalid or has expired.");
                    return "registration-failed";
                }
            } else {
                emailHint = claims.email;
                return "login-for-registration-required";
            }
        default:
            console.warn("The token loaded from the URL has an unknown audience and can not be processed.");
            return "unknown-token";
    }
}

export async function login(username: string, password: string, sessKey: string): Promise<[Session, Status]> {
    const resp = await api.login(username, password);
    const sess = sessionFromTokenResponse(sessKey, resp);
    sess.store();

    if (token) {
       const status = await consumeToken(sess, token);
       switch (status) {
           case "email-confirmed":
           case "email-confirmation-failed":
           case "registration-completed":
           case "registration-failed":
           case "unknown-token":
               token = null;
       }
    }

    return [sess, "login"];
}

function sessionFromTokenResponse(key: string, resp: api.TokenResponse): Session {
    const now = new Date();
    return new Session(
        key,
        resp.access_token,
        resp.refresh_token!, // always returned by the server
        resp.scope ? resp.scope.split(" ") : [],
        now,
        new Date(now.getTime() + resp.expires_in * 1000),
        resp.id_token!, // always returned by the server
    );
}

// export function requiresPasswordReset(): boolean {
//     return resetPasswordToken != null;
// }

export function getEmailHint(): string | null {
    return emailHint;
}

export async function resetPassword(newPassword: string): Promise<void> {
    if (!token) throw new Error("No token loaded from the URL.");
    const claims = parseToken(token) as PasswordResetTokenClaims;
    if (claims.aud !== "_reset_password") throw new Error("The token loaded from the URL is not a password reset token.");
    await api.resetPassword(token, newPassword);
    token = null;
}

export function register(user: api.NewUser, password: string, redirectUri = document.location.href): Promise<void> {
    return api.register(user, password, redirectUri);
}

export function instructPasswordReset(email: string, redirectUri = document.location.href): Promise<void> {
    return api.instructPasswordReset(email, redirectUri);
}

export function socialLoginUri(iss: string, redirectUri = document.location.href) {
    return api.socialLoginUri(iss, redirectUri);
}

function parseToken(token: string): any {
    const parts = token.split(".");
    return JSON.parse(atob(parts[1]));
}

function createToken(u: Userinfo): string {
    const jwtHeaderAlgNone = {
        alg: "none",
        typ: "JWT",
    };
    return btoa(JSON.stringify(jwtHeaderAlgNone)) + "." + btoa(JSON.stringify(u)) + ".";

}