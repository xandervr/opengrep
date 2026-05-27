import { data as taintedData } from "./pkg_a/source";
import { data as safeData } from "./pkg_b/source";

function main() {
  sink(taintedData);
  sink(safeData);
}
