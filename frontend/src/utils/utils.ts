export const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
export const escapeRegex = (value: string) => value.replace(/[-\/\\^$.*+?()[\]{}|]/g, "\\$&");
export const isValidQuery = (query: string) => query && query.trim() !== "";

export const isValidRedirectUri = (value: string) => {
    if (!isValidQuery(value)) {
        return false;
    }

    try {
        new URL(value);
    } catch {
        return false;
    }

    return true;
}