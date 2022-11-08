import { Fetcher } from "@halliday/rest";
import { OAuth2ErrorStatus, Session, SessionEvent, SessionEventType, Status as SessionStatus } from "./session";
import * as api from "./api";

export type IdentityStatus =
    "no-session" |
    "login" | "logout" |
    "userinfo" |
    "refreshed" | "revoked" | "loaded" |
    "email-confirmed" | "email-confirmation-failed" | "login-for-email-confirmation-required" |
    "password-reset-required" |
    "registration-completed" | "registration-failed" | "login-for-registration-required" |
    "social-login-exchanged" | "social-login-failed" |
    "unknown-token" |
    "invalid-subject" |
    `oauth2-${OAuth2ErrorStatus}` |
    `session-${SessionEventType}`;

export class IdentityEvent {
    constructor(public type: string, public name: string) { }
}

export type IdentityListener = (event: IdentityEvent) => void;

export const defaultKey = "session";

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

class IdentityManager {

    key = defaultKey;
    session: Session | null = null;

    status: IdentityStatus = "no-session";
    err: any = null;

    //

    private store() {
        if (this.session) {
            localStorage.setItem(this.key, this.session.toURLSearchParams().toString());
        }
    }

    private handleSessionEvent(ev: SessionEvent) {

    }

    private setSession(session: Session | null) {
        if(this.session) {
            this.session.removeEventListener("refresh", this.handleSessionEvent);
            this.session.removeEventListener("userinfo", this.handleSessionEvent);
        }
        this.session = session;
        if(this.session) {
            this.session.addEventListener("refresh", this.handleSessionEvent);
            this.session.addEventListener("userinfo", this.handleSessionEvent);
        }
    }

    //

    async reviveSession(): Promise<Session | null> {
        const storage = localStorage.getItem(this.key);
        if (!storage) {
            this.setSession(null);
            this.status = "no-session";
            return null;
        }

        const params = new URLSearchParams(storage);
        const accessToken = params.get("access_token")!;
        const refreshToken = params.get("refresh_token")!;
        const scope = params.get("scope")!;
        const scopes = scope === "" ? [] : scope.split(" ");
        const expiresAt = new Date(parseInt(params.get("expires_at")!) * 1000);
        const issuedAt = new Date(parseInt(params.get("issued_at")!) * 1000);
        const idToken = params.get("id_token")!;
        const sess = new Session(accessToken, refreshToken, scopes, issuedAt, expiresAt, idToken);

        if (sess.nearlyExpired && sess.refreshToken) {
            try {
                await sess.refresh();
                this.session = sess;
                return sess;
            } catch (err) {
                console.warn("The session could not be refreshed. The token loaded from local storage might be expired or was revoked.");
                localStorage.removeItem(this.key);
                this.status = "revoked";
                this.err = err;
                this.session = null;
                return null;
            }
        }
        try {
            await sess.fetchUserinfo();
        } catch (err) {
            localStorage.removeItem(this.key);
            this.status = "revoked";
            this.err = err;
            this.session = null;
            return null;
        }

        this.session = sess;
        return sess;
    }

    fetch = async (req: Request, fetcher: Fetcher = globalThis.fetch) => {
        if (!this.session) return fetcher(req);
        return this.session.fetch(req, fetcher);
    }

    public emailHint: string | null = null;
    private token: string | null = null;

    async loadSession(): Promise<Session | null> {
        // 1 - check for a session in local storage
        this.session = await this.reviveSession();
        if (this.session) return this.session;

        // 2 - check for a token in the URL that might require some action
        const hash = new URLSearchParams(location.hash.slice(1));
        this.token = hash.get("token");
        if (this.token) {
            stripHashParams("token");
            await this.consumeToken();
            if (this.status === "invalid-subject") {
                try {
                    await this.session!.logout();
                } catch (err) {
                    // log error but discard anyways
                    console.warn("The old session could not be logged out:", err);
                }
                this.session = null;
                await this.consumeToken();
            }
            switch (this.status) {
                case "email-confirmed":
                case "email-confirmation-failed":
                case "registration-completed":
                case "registration-failed":
                case "unknown-token":
                    this.token = null;
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
                this.status = "social-login-exchanged";
            } catch (err) {
                console.warn("The social login could not be completed. The token loaded from the URL is invalid or has expired.");
                this.status = "social-login-failed";
            }
            if (resp) {
                this.session = Session.fromTokenResponse(resp);
                this.store();
            }
        }

        const error = search.get("error") ?? hash.get("error") ?? undefined;
        if (error) {
            const errorDescription = search.get("error_description") ?? hash.get("error_description") ?? undefined;
            const errorUri = search.get("error_uri") ?? hash.get("error_uri") ?? undefined;
            stripParams("error", "error_description", "error_uri", "state");
            console.warn("OAuth2 error:", error, errorDescription, errorUri);
            this.status = `oauth2-${error as OAuth2ErrorStatus}`;
        }

        return this.session;
    }

    private async consumeToken(): Promise<void> {
        if(!this.token) return;

        const redirectUri = new URLSearchParams(location.hash.slice(1)).get("redirect_uri") || undefined;
        const claims = parseToken(this.token) as ChangeEmailTokenClaims | PasswordResetTokenClaims | RegistrationTokenClaims;
        if (this.session && this.session.sub !== claims.sub) {
            this.status = "invalid-subject";
            return;
        }

        switch (claims.aud) {
            case "_change_email":
                if (this.session) {
                    const email = claims.email;
                    try {
                        await api.changeEmail(this.token, redirectUri, { fetcher: this.fetch });
                        if (this.session.userinfo) {
                            this.session.userinfo = { ...this.session.userinfo, email, email_verified: true };
                            // TODO emit event for userinfo change
                        }
                        this.status = "email-confirmed";
                        this.token = null;
                        return;
                    } catch (err) {
                        console.warn("The email change could not be completed. The token loaded from the URL is invalid or has expired.");
                        this.status = "email-confirmation-failed";
                        this.token = null;
                        return;
                    }
                } else {
                    this.emailHint = claims.email;
                    this.status = "login-for-email-confirmation-required";
                    return
                }

            case "_reset_password":

                this.emailHint = claims.email;
                this.status = "password-reset-required";
                return

            case "_complete_registration":

                if (this.session) {
                    try {
                        await api.completeRegistration(this.token, redirectUri, { fetcher: this.fetch });
                        if (this.session.userinfo) {
                            this.session.userinfo = { ...this.session.userinfo, email_verified: true };
                            this.session.store();
                        }
                        await this.session.refresh();

                        this.status = "registration-completed";
                        this.token = null;
                        return
                    } catch (err) {
                        console.warn("The registration could not be completed. The token loaded from the URL is invalid or has expired.");
                        this.status = "registration-failed";
                        this.token = null;
                        return
                    }
                } else {
                    this.emailHint = claims.email;
                    this.status = "login-for-registration-required";
                    return
                }
            default:
                console.warn("The token loaded from the URL has an unknown audience and can not be processed.");
                this.status = "unknown-token";
                this.token = null;
                return
        }
    }

    //

    async login(username: string, password: string): Promise<Session> {
        const resp = await api.login(username, password);
        this.session = Session.fromTokenResponse(this.key, resp);
        this.session.store();
    
        if (this.token) {
            await this.consumeToken();
        }
    
        return this.session;
    }

    async resetPassword(newPassword: string): Promise<void> {
        if (!this.token) throw new Error("No token loaded from the URL.");
        const claims = parseToken(this.token) as PasswordResetTokenClaims;
        if (claims.aud !== "_reset_password") throw new Error("The token loaded from the URL is not a password reset token.");
        await api.resetPassword(this.token, newPassword);
        this.token = null;
    }
    

    //

    private listeners: { [key: string]: Set<IdentityListener> } = {};

    addEventListener(ev: string, l: IdentityListener) {
        if (!this.listeners[ev]) {
            this.listeners[ev] = new Set();
        }
        this.listeners[ev].add(l);
    }

    removeEventListener(ev: string, l: IdentityListener) {
        if (!this.listeners[ev]) {
            return;
        }
        this.listeners[ev].delete(l);
    }
}

const ident = new IdentityManager();
export default ident;

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