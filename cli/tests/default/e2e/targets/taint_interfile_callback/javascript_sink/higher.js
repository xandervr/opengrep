import { sourceSink } from "./source";

export function applySink(callback) {
  callback(sourceSink());
}
