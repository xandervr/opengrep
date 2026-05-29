import { source } from "./source";

export function apply(callback) {
  return callback(source());
}
