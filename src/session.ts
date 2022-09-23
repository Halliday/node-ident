import { Fetcher } from "@halliday/rest";
import * as api from "./api";
import { stripSearchParams } from "./tools";
// import { NewUser, Userinfo } from "./user";

export const nearlyExpiredThreshold = 30 * 1000; // 1 minute
export const defaultKey = "session";

export type Userinfo = api.Userinfo;
export type User = api.User;
export type UserUpdate = api.UserUpdate;
export type NewUser = api.NewUser;

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

    async refresh(scope?: string): Promise<void> {
        if (this.pendingRefresh)
            return this.pendingRefresh;
        this.pendingRefresh = (async (): Promise<void> => {
            const resp = await api.token({
                grant_type: "refresh_token",
                refresh_token: this.refreshToken,
                scope: scope,
            });
            this.accessToken = resp.access_token;
            this.refreshToken = resp.refresh_token ?? this.refreshToken;
            this.scopes = resp.scope === undefined ? this.scopes : (resp.scope === "" ? [] : resp.scope.split(" "));
            this.issuedAt = new Date();
            this.expiresAt = new Date(this.issuedAt.getTime() + resp.expires_in * 1000);
            this.idToken = resp.id_token || this.idToken;
            this.userinfo = parseToken(this.idToken);
            this.store();
        })();
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
        await api.updateUsersSelf(u, {fetcher: this.fetch});
        if (this.userinfo) {
            this.userinfo = {...this.userinfo, ...u};
            this.idToken = createToken(this.userinfo);
            this.store();
        }
    }

    deleteSelf() {
        return api.deleteUsersSelf({fetcher: this.fetch});
    }

    fetchUserinfo() {
        return api.userinfo({fetcher: this.fetch});
    }

    logout() {
        this.delete();
        return api.logout(this.refreshToken);
    }

    delete() {
        deleteSession(this.key);
    }

    instructEmailChange(email: string, redirectUri = document.location.href): Promise<void> {
        return api.instructEmailChange(email, redirectUri, {fetcher: this.fetch});
    }
}

export function deleteSession(key = defaultKey) {
    localStorage.removeItem(key);
}

let passwordResetEmail = "";
let resetPasswordToken: string | null = null;

type ChangeEmailTokenClaims = {
    sub: string,
    email: string
}

type AccessTokenClaims = {
    sub: string,
    scope: string
}

export async function loadSession(key = defaultKey): Promise<[sess: Session | null, reason: string]> {
    let sess: Session | null = null;
    let reason = "none";

    // 1 - check for a session in local storage

    const storage = localStorage.getItem(key);
    if (storage) {
        const params = new URLSearchParams(storage);
        const accessToken = params.get("access_token")!;
        const refreshToken = params.get("refresh_token")!;
        const scope = params.get("scope")!;
        const scopes = scope === "" ? [] : scope.split(" ");
        const expiresAt = new Date(parseInt(params.get("expires_at")!) * 1000);
        const issuedAt = new Date(parseInt(params.get("issued_at")!) * 1000);
        const idToken = params.get("id_token")!;
        sess = new Session(key, accessToken, refreshToken, scopes, issuedAt, expiresAt, idToken);

        if (sess.nearlyExpired) {
            try {
                await sess.refresh();
                reason = "refresh";
            } catch (err) {
                console.warn("The session could not be refreshed. The token loaded from local storage might be expired or was revoked.");
                reason = "session-revoked";
                deleteSession(key);
            }
            if (sess) {
                sess.store();
            }
        }
    }

    // 2 - check for a registration_token in the URL (that was sent by email) and complete the registration by API call

    const search = new URLSearchParams(window.location.search);
    const hash = new URLSearchParams(location.hash.slice(1));

    const registrationToken = search.get("registration_token");
    if (registrationToken) {
        stripSearchParams("registration_token");
        try {
            await api.completeRegistration(registrationToken);
            reason = "registration-completed";
        } catch (err) {
            console.warn("The registration could not be completed. The token loaded from the URL is invalid or has expired.");
            reason = "registration-failed";
        }
    }

    // 3 - check for a password_reset_token in the URL (that was sent by email)

    resetPasswordToken = search.get("password_reset_token");
    if (resetPasswordToken) {
        const claims = JSON.parse(atob(resetPasswordToken.split(".")[1])) as Record<string, any>;
        passwordResetEmail = claims.email as string;
        stripSearchParams("password_reset_token");
        console.info("Password reset token loaded from URL. The user will be prompted to enter a new password.");
        reason = "password-reset";
    }

    // 4 - check for a change_email_token in the URL (that was sent by email)

    const changeEmailToken = search.get("change_email_token");
    if (changeEmailToken) {
        const redirectUri = search.get("redirect_uri") ?? undefined;
        stripSearchParams("change_email_token", "redirect_uri");
        try {
            await api.changeEmail(changeEmailToken, redirectUri);
            reason = "email-confirmed";
        } catch (err) {
            console.warn("The registration could not be completed. The token loaded from the URL is invalid or has expired.");
            reason = "email-confirmation-failed";
        }
        if (sess && sess.userinfo) {
            const {sub, email} = parseToken(changeEmailToken) as ChangeEmailTokenClaims;
            if (sub === sess.userinfo.sub) {
                sess.userinfo.email = email;
                sess.idToken = createToken(sess.userinfo);
                sess.store();
            } else {
                try {
                    await sess.logout();
                } catch (err) {
                    console.warn("The session could not be logged out.");
                }
            }
        }
    }

    // 5 - check for an code or access_token in the URL, as returned by an OAuth2 authorization server (e.g. a social login provider)

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
        stripSearchParams("code", "access_token", "token_type", "expires_in", "scope", "id_token", "state");
        location.hash = "";

        let resp: api.TokenResponse | undefined;
        try {
            resp = await api.exchangeSocialLogin({code, access_token, token_type, expires_in, scope, id_token, state} as api.AuthResponse);
            reason = "social-login-exchanged";
        } catch(err) {
            console.warn("The social login could not be completed. The token loaded from the URL is invalid or has expired.");
            reason = "social-login-failed";
        }
        if (resp) {
            sess = sessionFromTokenResponse(key, resp);
            sess.store();
        }
    }

    const error = search.get("error") ?? hash.get("error") ?? undefined;
    if (error) {
        stripSearchParams("error");
        location.hash = "";
        reason = error;
    }

    return [sess, reason];
}

export async function login(username:string, password: string, sessKey: string) {
    const resp = await api.login(username, password);
    const sess = sessionFromTokenResponse(sessKey, resp);
    sess.store();
    return sess;
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

export function requiresPasswordReset(): boolean {
    return resetPasswordToken != null;
}

export function getPasswordResetEmail(): string {
    return passwordResetEmail;
}

export async function resetPassword(newPassword: string): Promise<void> {
    await api.resetPassword(resetPasswordToken!, newPassword);
    resetPasswordToken = null;
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
    return btoa(JSON.stringify(jwtHeaderAlgNone))+"."+btoa(JSON.stringify(u))+".";

}