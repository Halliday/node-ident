import { Fetcher } from "@halliday/rest";
import { ChangeEmailTokenClaims, PasswordResetTokenClaims, RegistrationTokenClaims, Session, SessionEvent, SessionEventType, User, Userinfo } from "./session";
import * as api from "./api";

export type OAuth2ErrorStatus = "invalid_request" | "unauthorized_client" | "access_denied" | "unsupported_response_type" | "invalid_scope" | "server_error" | "temporarily_unavailable";

export type IdentityEventType =
    "session" |
    "login" | "logout" | "revoke" |
    "email-verify" | "email-verify-error" | "login-for-email-verify-required" |
    "password-reset-required" |
    "register" | "registration-complete" | "registration-error" | "login-for-registration-required" |
    "social-login" | "social-login-error" |
    "unknown-token" |
    "invalid-subject" |
    `oauth2-${OAuth2ErrorStatus}` |
    SessionEventType;

export class IdentityEvent {
    constructor(
        readonly ident: IdentityManager,
        readonly type: IdentityEventType,
        readonly err?: any) { }
}

export class IdentityError {
    constructor(
        readonly ident: IdentityManager,
        readonly type: IdentityEventType,
        readonly cause?: any) { }
}

export type IdentityListener = (event: IdentityEvent) => void;

export const defaultKey = "session";

// type AccessTokenClaims = {
//     sub: string,
//     scope: string
// }

const sessionEvents: SessionEventType[] = [
    "refresh", "userinfo", "delete-user",
];

class IdentityManager {
    session: Session | null;

    constructor(readonly key = defaultKey) {
        this.session = this.loadLastSessionFromStorage();
        if (this.session) {
            for(const ev of sessionEvents)
                this.session.addEventListener(ev, this.handleSessionEvent);
        }
    }

    get sub(): string | null {
        return this.session?.sub ?? null;
    }

    get user(): User | null {
        return this.session?.user ?? null;
    }

    //

    private store() {
        if (this.session) {
            localStorage.setItem(this.key, this.session.toURLSearchParams().toString());
        }
    }

    private handleSessionEvent = (ev: SessionEvent) => {
        this.store();
        this.emit(ev.type, ev.err);
        if (ev.type === "delete-user") {
            localStorage.removeItem(this.key);
            this.setSession(null);
        }
    }

    private setSession(session: Session | null) {
        if (this.session === session) return;
        if (this.session) {
            for(const ev of sessionEvents)
                this.session.removeEventListener(ev, this.handleSessionEvent);
        }
        this.session = session;
        if (this.session) {
            for(const ev of sessionEvents)
                this.session.addEventListener(ev, this.handleSessionEvent);
        }
        this.emit("session");
    }

    //

    private loadLastSessionFromStorage(): Session | null {
        const storage = localStorage.getItem(this.key);
        if (!storage) return null;

        const params = new URLSearchParams(storage);
        const accessToken = params.get("access_token");
        if (!accessToken) {
            console.log("There is a session in storage, but it has no access token.");
            localStorage.removeItem(this.key);
            throw null;
        }
        const refreshToken = params.get("refresh_token");
        const scope = params.get("scope")!;
        const scopes = scope === "" ? [] : scope.split(" ");
        const expiresAt = new Date(parseInt(params.get("expires_at")!) * 1000);
        const issuedAt = new Date(parseInt(params.get("issued_at")!) * 1000);
        const idToken = params.get("id_token")!;
        return new Session(accessToken, refreshToken, scopes, issuedAt, expiresAt, idToken);
    }

    fetch = async (req: Request, fetcher: Fetcher = globalThis.fetch) => {
        if (!this.session) return fetcher(req);
        return this.session.fetch(req, fetcher);
    }

    public emailHint: string | null = null;
    private token: string | null = null;

    async logout() {
        if (!this.session) return;
        localStorage.removeItem(this.key);
        try {
            await this.session!.logout();
        } catch (err) {
            // log error but discard anyways
            console.warn("The session could not be logged out:", err);
        }
        this.setSession(null);
        this.emit("logout");
    }

    private setupCalled = false;

    // Setup performs initial work for the identity manager.
    // It loads the last session from local storage and tries to resume it.
    // This function must be called once.
    async setup(): Promise<void> {
        if (this.setupCalled) return;
        this.setupCalled = true;

        // check for a token in the URL that might require some action
        const hash = new URLSearchParams(location.hash.slice(1));
        this.token = hash.get("token");
        if (this.token) stripHashParams("token");

        if (this.token) {
            try {
                await this.consumeToken();
            } catch (err) {
                if (err instanceof IdentityError) {
                    if (err.type === "invalid-subject") {
                        localStorage.removeItem(this.key);
                        try {
                            await this.session!.logout();
                        } catch (err) {
                            // log error but discard anyways
                            console.warn("The old session could not be logged out:", err);
                        }
                        this.setSession(null);
                        // try again without a session
                        await this.consumeToken();
                        return;
                    } else {
                        throw err;
                    }
                } else {
                    throw err;
                }
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
                const session = Session.fromTokenResponse(resp);
                this.setSession(session);
                this.store();
                this.emit("social-login");
                return;
            } catch (err) {
                console.warn("The social login could not be completed. The token loaded from the URL is invalid or has expired.");
                this.emit("social-login-error", err);
                return;
            }
        }

        const error = search.get("error") ?? hash.get("error") ?? undefined;
        if (error) {
            const errorDescription = search.get("error_description") ?? hash.get("error_description") ?? undefined;
            const errorUri = search.get("error_uri") ?? hash.get("error_uri") ?? undefined;
            stripParams("error", "error_description", "error_uri", "state");
            console.warn("OAuth2 error:", error, errorDescription, errorUri);
            this.emit(`oauth2-${error as OAuth2ErrorStatus}`);
            return;
        }
    }

    requiresLogin(): boolean {
        const token = this.token;
        if(!token || this.session) return false;
        const claims = parseToken(token) as ChangeEmailTokenClaims | PasswordResetTokenClaims | RegistrationTokenClaims;
        return claims.aud === "_change_email" || claims.aud === "_complete_registration";
    }

    private async consumeToken(): Promise<void> {
        if (!this.token) throw new Error("no token");

        const redirectUri = new URLSearchParams(location.hash.slice(1)).get("redirect_uri") || undefined;
        const claims = parseToken(this.token) as ChangeEmailTokenClaims | PasswordResetTokenClaims | RegistrationTokenClaims;
        if (this.session && this.session.sub !== claims.sub) {
            throw new IdentityError(this, "invalid-subject");
        }

        switch (claims.aud) {
            case "_change_email":
                if (this.session) {
                    try {
                        await this.session.changeEmail(this.token, redirectUri);
                        this.token = null;
                        this.emit("email-verify");
                    } catch (err) {
                        console.warn("The email change could not be completed. The token loaded from the URL is invalid or has expired.");
                        this.token = null;
                        this.emit("email-verify-error", err);
                        return;
                    }
                } else {
                    this.emailHint = claims.email;
                    this.emit("login-for-email-verify-required");
                    return
                }

            case "_reset_password":

                this.emailHint = claims.email;
                this.emit("password-reset-required");
                return

            case "_complete_registration":

                if (this.session) {
                    try {
                        await this.session.completeRegistration(this.token, redirectUri);
                        this.token = null;
                        this.emit("registration-complete");
                        return;
                    } catch (err) {
                        console.warn("The registration could not be completed. The token loaded from the URL is invalid or has expired.");
                        this.token = null;
                        this.emit("registration-error", err);
                        return;
                    }
                } else {
                    this.emailHint = claims.email;
                    this.emit("login-for-registration-required");
                    return;
                }
            default:
                console.warn("The token loaded from the URL has an unknown audience and can not be processed.");
                this.token = null;
                this.emit("unknown-token");
                return;
        }
    }

    //

    async login(username: string, password: string): Promise<Session> {
        const resp = await api.login(username, password);
        const session = Session.fromTokenResponse(resp);
        this.setSession(session);
        this.store();
        this.emit("login");
        if (this.token) await this.consumeToken();
        return session;
    }

    async resetPassword(newPassword: string): Promise<void> {
        if (!this.token) throw new Error("No token loaded from the URL.");
        const claims = parseToken(this.token) as PasswordResetTokenClaims;
        if (claims.aud !== "_reset_password") throw new Error("The token loaded from the URL is not a password reset token.");
        await api.resetPassword(this.token, newPassword);
        this.token = null;
    }


    //

    private listeners: { [type: string]: Set<IdentityListener> } = {};

    addEventListener(type: IdentityEventType, l: IdentityListener): void {
        if (!this.listeners[type]) this.listeners[type] = new Set();
        this.listeners[type].add(l);
    }

    removeEventListener(type: IdentityEventType, l: IdentityListener): void {
        if (!this.listeners[type]) return;
        this.listeners[type].delete(l);
    }

    private emit(status: IdentityEventType, err?: any): void {
        console.log("emit", status, err);
        if (!this.listeners[status]) return;
        const ev = new IdentityEvent(this, status, err);
        for (const l of this.listeners[status]) {
            try {
                l(ev);
            } catch (err) {
                console.error("Error in session event listener", err);
            }
        }
    }

    //

    async register(user: api.NewUser, password: string, redirectUri = document.location.href): Promise<void> {
        if(!user.email) throw new Error("email is required");
        await api.register(user, password, redirectUri);
        const resp = await api.login(user.email, password);
        const session = Session.fromTokenResponse(resp);
        this.setSession(session);
        this.store();
        this.emit("register");
    }

    instructPasswordReset(email: string, redirectUri = document.location.href): Promise<void> {
        return api.instructPasswordReset(email, redirectUri);
    }

    instructEmailChange(email: string, redirectUri = document.location.href): Promise<void> {
        return api.instructEmailChange(email, redirectUri);
    }

    socialLoginUri(iss: string, redirectUri = document.location.href) {
        return api.socialLoginUri(iss, redirectUri);
    }
}

const ident = new IdentityManager();
export default ident;
(globalThis as any)["ident"] = ident;

////////////////////////////////////////////////////////////////////////////////

function parseToken(token: string): any {
    const parts = token.split(".");
    return JSON.parse(atob(parts[1]));
}


export function stripParams(...params: string[]) {
    const url = new URL(location.href);

    const search = new URLSearchParams(url.search);
    for (const param of params) {
        search.delete(param);
    }
    url.search = search.toString();

    const hash = new URLSearchParams(url.hash.substring(1));
    for (const param of params) {
        hash.delete(param);
    }
    url.hash = hash.toString();

    history.replaceState(history.state, document.title, url);
}

export function stripSearchParams(...params: string[]) {
    const url = new URL(location.href);
    const search = new URLSearchParams(url.search);
    for (const param of params) {
        search.delete(param);
    }
    url.search = search.toString();
    history.replaceState(history.state, document.title, url);
}

export function stripHashParams(...params: string[]) {
    const url = new URL(location.href);
    const hash = new URLSearchParams(url.hash.substring(1));
    for (const param of params) {
        hash.delete(param);
    }
    url.hash = hash.toString();
    history.replaceState(history.state, document.title, url);
}