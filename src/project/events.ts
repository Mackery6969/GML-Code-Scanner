/** GameMaker object event, derived from an event file name such as `Step_2.gml`. */
export interface EventInfo {
  /** File-name prefix: Create, Step, Draw, Other, Collision, ... */
  kind: string;
  /** Event number (or collision object name for Collision events). */
  num: number;
  collisionObject?: string;
  /** Human readable name as shown in the GameMaker IDE, e.g. "End Step". */
  displayName: string;
  /** GameMaker eventType id used in the object .yy `eventList`. */
  eventType: number;
}

const EVENT_TYPES: Record<string, number> = {
  Create: 0,
  Destroy: 1,
  Alarm: 2,
  Step: 3,
  Collision: 4,
  Keyboard: 5,
  Mouse: 6,
  Other: 7,
  Draw: 8,
  KeyPress: 9,
  KeyRelease: 10,
  Trigger: 11,
  CleanUp: 12,
  Gesture: 13,
  PreCreate: 14,
};

const OTHER_NAMES: Record<number, string> = {
  0: "Outside Room",
  1: "Intersect Boundary",
  2: "Game Start",
  3: "Game End",
  4: "Room Start",
  5: "Room End",
  6: "No More Lives",
  7: "Animation End",
  8: "Path Ended",
  9: "No More Health",
  30: "Close Button",
  58: "Animation Update",
  59: "Animation Event",
  60: "Async - Image Loaded",
  61: "Async - Sound Loaded",
  62: "Async - HTTP",
  63: "Async - Dialog",
  66: "Async - In-App Purchase",
  67: "Async - Cloud",
  68: "Async - Networking",
  69: "Async - Steam",
  70: "Async - Social",
  71: "Async - Push Notification",
  72: "Async - Save/Load",
  73: "Async - Audio Recording",
  74: "Async - Audio Playback",
  75: "Async - System",
  76: "Broadcast Message",
};

const DRAW_NAMES: Record<number, string> = {
  0: "Draw",
  64: "Draw GUI",
  65: "Window Resize",
  72: "Draw Begin",
  73: "Draw End",
  74: "Draw GUI Begin",
  75: "Draw GUI End",
  76: "Pre-Draw",
  77: "Post-Draw",
};

const STEP_NAMES: Record<number, string> = { 0: "Step", 1: "Begin Step", 2: "End Step" };

/** Parses `Step_0`, `Collision_obj_wall`, `Other_62`, ... (without extension). */
export function parseEventFileName(base: string): EventInfo | undefined {
  const m = /^([A-Za-z]+)_(.+)$/.exec(base);
  if (!m) return undefined;
  const kind = m[1];
  if (!Object.hasOwn(EVENT_TYPES, kind)) return undefined;
  const eventType = EVENT_TYPES[kind];
  if (kind === "Collision") {
    return { kind, num: 0, collisionObject: m[2], displayName: `Collision (${m[2]})`, eventType };
  }
  const num = Number(m[2]);
  if (!Number.isInteger(num)) return undefined;
  let displayName: string;
  switch (kind) {
    case "Step":
      displayName = STEP_NAMES[num] ?? `Step ${num}`;
      break;
    case "Draw":
      displayName = DRAW_NAMES[num] ?? `Draw ${num}`;
      break;
    case "Other":
      displayName = num >= 10 && num <= 25 ? `User Event ${num - 10}` : num >= 40 && num <= 47 ? `Outside View ${num - 40}` : num >= 50 && num <= 57 ? `Intersect View ${num - 50} Boundary` : (OTHER_NAMES[num] ?? `Other ${num}`);
      break;
    case "Alarm":
      displayName = `Alarm ${num}`;
      break;
    case "CleanUp":
      displayName = "Clean Up";
      break;
    case "PreCreate":
      displayName = "Pre-Create";
      break;
    case "KeyPress":
      displayName = `Key Press ${num}`;
      break;
    case "KeyRelease":
      displayName = `Key Release ${num}`;
      break;
    default:
      displayName = num === 0 && (kind === "Create" || kind === "Destroy") ? kind : `${kind} ${num}`;
  }
  return { kind, num, displayName, eventType };
}

/** Runs every frame: Begin Step, Step, End Step. */
export function isStepEvent(e: EventInfo | undefined): boolean {
  return e?.kind === "Step";
}

/** Any draw-category event that renders (excludes Window Resize). */
export function isDrawEvent(e: EventInfo | undefined): boolean {
  return e?.kind === "Draw" && e.num !== 65;
}

/** Events that run every frame. */
export function isPerFrameEvent(e: EventInfo | undefined): boolean {
  return isStepEvent(e) || isDrawEvent(e);
}

export function isAsyncEvent(e: EventInfo | undefined): boolean {
  return e?.kind === "Other" && e.num >= 60 && e.num <= 76 && e.num !== 64 && e.num !== 65;
}
