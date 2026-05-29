import { getInput } from "./source";
import { addItem } from "./helpers";

function main() {
  const bag = [];
  addItem(bag, getInput());
  sink(bag);
}
