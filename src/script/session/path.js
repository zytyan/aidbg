import { cwd } from "aidbg:files";

export const sep = "/";
function checked(path) {
    if (typeof path !== "string") throw new TypeError("expected a path string");
    return path;
}

export function isAbsolute(path) { return checked(path).startsWith(sep); }
export function normalize(path) {
    const absolute = isAbsolute(path);
    const parts = [];
    for (const segment of path.split(sep)) {
        if (!segment || segment === ".") continue;
        if (segment !== "..") parts.push(segment);
        else if (parts.length && parts.at(-1) !== "..") parts.pop();
        else if (!absolute) parts.push(segment);
    }
    const result = (absolute ? sep : "") + parts.join(sep) || ".";
    return result !== sep && path.endsWith(sep) ? result + sep : result;
}

export function join(...parts) { return normalize(parts.map(checked).filter(Boolean).join(sep)); }
export function resolve(...parts) {
    let result = "";
    for (let index = parts.length - 1; index >= -1; index--) {
        const part = index < 0 ? cwd() : checked(parts[index]);
        if (!part) continue;
        result = result ? part + sep + result : part;
        if (isAbsolute(part)) break;
    }
    return normalize(result).replace(/\/$/, "") || sep;
}

export function relative(from, to) {
    const source = resolve(from).slice(1).split(sep).filter(Boolean);
    const destination = resolve(to).slice(1).split(sep).filter(Boolean);
    let common = 0;
    while (common < source.length && source[common] === destination[common]) common++;
    return [...source.slice(common).map(() => ".."), ...destination.slice(common)].join(sep);
}

export function dirname(path) {
    const absolute = isAbsolute(path);
    const slash = path.replace(/\/+$/, "").lastIndexOf(sep);
    if (slash <= 0) return absolute ? sep : ".";
    return absolute && slash === 1 ? "//" : path.slice(0, slash);
}

export function basename(path, suffix) {
    const trimmed = checked(path).replace(/\/+$/, "");
    const start = trimmed.lastIndexOf(sep) + 1;
    const base = trimmed.slice(start);
    if (suffix === undefined || !checked(suffix) || suffix.length > path.length) return base;
    if (suffix === path) return "";
    if (suffix.length < base.length && base.endsWith(suffix)) {
        return base.slice(0, -suffix.length);
    }
    if (suffix.length > base.length && suffix.endsWith(base)) return path.slice(start);
    return base;
}

export function extname(path) {
    const base = basename(path);
    const dot = base.lastIndexOf(".");
    return dot > 0 && base !== ".." ? base.slice(dot) : "";
}

export function parse(path) {
    const root = isAbsolute(path) ? sep : "";
    const base = basename(path);
    const end = path.replace(/\/+$/, "").lastIndexOf(sep);
    const ext = end === 0 && base === ".." ? "." : extname(path);
    const dir = end > 0 ? path.slice(0, end) : root;
    return {root, dir, base, ext, name:base.slice(0, base.length - ext.length)};
}

export function format(path) {
    if (path === null || typeof path !== "object") throw new TypeError("expected a parsed path object");
    const dir = path.dir || path.root;
    const ext = path.ext || "";
    const base = path.base || (path.name || "") + (ext && !ext.startsWith(".") ? "." + ext : ext);
    return dir ? dir + (dir === path.root ? "" : sep) + base : base;
}

export default {sep, isAbsolute, normalize, join, resolve, relative, dirname, basename, extname, parse, format};
