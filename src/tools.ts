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