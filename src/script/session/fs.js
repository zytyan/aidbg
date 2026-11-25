import { sync } from "aidbg:files";

export function readFileSync(path, options) {
    const encoding = typeof options === "string" ? options : options?.encoding;
    if (encoding != null && encoding !== "utf8" && encoding !== "utf-8") {
        throw new TypeError("expected UTF-8 encoding");
    }
    return sync("read", path, encoding == null ? 0 : 1);
}

export function readdirSync(path) { return sync("readdir", path); }
export function accessSync(path, mode = constants.F_OK) { return sync("access", path, mode); }
export function existsSync(path) { return sync("exists", path); }
export function realpathSync(path) { return sync("realpath", path); }
export const constants = Object.freeze({F_OK:0, R_OK:4, W_OK:2, X_OK:1});

export function statSync(path) {
    const {size, file, directory} = sync("stat", path);
    return {size, isFile:() => file, isDirectory:() => directory};
}

export default {readFileSync, readdirSync, accessSync, existsSync, realpathSync, statSync, constants};
