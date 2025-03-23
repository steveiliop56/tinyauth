export const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
export const isQueryValid = (value: string) => value.trim() !== "" && value !== "null";
