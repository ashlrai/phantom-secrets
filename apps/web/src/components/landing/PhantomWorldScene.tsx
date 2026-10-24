import { PhantomWorld } from "./PhantomWorld";
import markup from "./phantom-world-markup.json";

export function PhantomWorldScene() {
  // Static first-party markup pinned to the audited Hub scene; never user input.
  return <PhantomWorld><div dangerouslySetInnerHTML={{ __html: markup }} /></PhantomWorld>;
}
