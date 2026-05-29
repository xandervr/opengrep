import { sourceReturn } from "./source";

export function applyReturn(callback) {
  return callback(sourceReturn());
}
