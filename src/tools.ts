export function stripSearchParams(...params: string[]) {
    const url = new URL(location.href);
    const search = new URLSearchParams(url.search);
    for (const param of params) {
        search.delete(param);
    }
    url.search = search.toString();
    history.replaceState(history.state, document.title, url);
}