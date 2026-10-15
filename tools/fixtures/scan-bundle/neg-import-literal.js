export const load = async () => {
    try {
        return await import("crypto");
    } catch {
        return undefined;
    }
};
