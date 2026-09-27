/** Local-only capture fixture: real application UI, fictional data, no transport.
 * This entry is outside the production build and never signs or sends records. */
import { mockIPC } from "@tauri-apps/api/mocks";
import type { Stream, View } from "../src/model";

const params = new URLSearchParams(location.search);
const family = params.get("audience") === "family";
localStorage.setItem("elo.appearance", params.get("theme") ?? "light");
localStorage.setItem("elo.biometricOffer.v1", "handled");
localStorage.setItem("elo.notificationOffer.v1", "handled");
localStorage.setItem(
  "elo.userPreferences.v1",
  JSON.stringify({
    uiScale: "system",
    language: "en",
    colorScheme: params.get("color") ?? "mint",
    colorOverrides: {},
    hideAvatars: false,
    motif: "elo",
    motifOpacity: 0.08,
  }),
);
const people = {
  alex: "Alex",
  maya: family ? "Mom" : "Maya",
  jules: family ? "Dad" : "Jules",
  sam: "Sam",
};
let serial = 0;
function message(
  person: keyof typeof people,
  text: string,
  minute: number,
  unread = false,
): Stream["rows"][number] {
  return {
    id: `marketing-message-${++serial}`,
    state: "STORED",
    unread,
    body: {
      kind: "chat.message",
      issuer_identity: person,
      created_at: `2026-09-14T09:${String(minute).padStart(2, "0")}:00Z`,
      payload: { text, sender_name: people[person] },
    },
  };
}
function chat(
  name: string,
  stream: string,
  rows: Stream["rows"],
  direct = false,
): Stream {
  return {
    name,
    stream,
    rows,
    space: "studio",
    space_context: "studio",
    head: "fixture",
    controller: "alex",
    recovery: null,
    forked: false,
    can_post: true,
    can_manage_members: true,
    chat_kind: direct ? "direct" : "chat",
    group: direct ? null : "work",
    owners: [{ identity_id: "alex" }],
    member_names: people,
    members: Object.keys(people).map((identity_id) => ({
      identity_id,
      external: false,
      capabilities: ["READ", "POST"],
      credential_ids: [identity_id],
    })),
    unread_count: rows.filter((row) => row.unread).length,
  };
}
const launch = chat(
  family ? "Birthday plans" : "Launch day",
  "launch",
  family
    ? [
        message(
          "maya",
          "Grandpa’s birthday is Saturday. Shall we all come over at 4?",
          20,
        ),
        message(
          "jules",
          "Perfect. I’ll pick him up so you can get everything ready.",
          22,
        ),
        message("alex", "Cake is sorted. Chocolate, of course. 🎂", 24),
        message("sam", "I’m on balloons and candles!", 26),
        message("maya", "Let’s keep the surprise in this chat. 🤫", 28),
        message("jules", "Can someone bring the photo album?", 30),
        message("alex", "Found it! There are some brilliant old pictures.", 32),
        message("sam", "I’ll make a playlist with his favourites.", 34),
        message("maya", "I’ll cook. Any requests for dinner?", 36),
        message("jules", "His favourite pasta gets my vote.", 40),
        message("sam", "Same here. I can bring a salad.", 45),
        message("alex", "I’ll be there at 3 to help set up.", 47),
        message("maya", "A whole family, one very happy Grandpa. 💛", 49),
      ]
    : [
        message("maya", "The new homepage is ready for a final look.", 20),
        message(
          "jules",
          "Love the direction. The mobile layout feels great.",
          22,
        ),
        message("alex", "Let’s keep launch updates in this channel.", 24),
        message("sam", "Copy is approved. We’re ready for Monday!", 26),
        message("maya", "One team. One good launch. ✨", 28),
        message(
          "sam",
          "The welcome email is ready too. I’ve added a quick getting-started guide.",
          30,
        ),
        message(
          "jules",
          "Nice! Can we include the three things people should try first?",
          32,
        ),
        message(
          "maya",
          "Join General, say hello to a teammate, and save a reminder.",
          34,
        ),
        message(
          "alex",
          "Exactly. Small steps, and a useful conversation from day one.",
          36,
        ),
        message(
          "sam",
          "Updated. The invite and guide are together in the launch checklist.",
          40,
        ),
        message(
          "jules",
          "I’ll be around after lunch to help the first teams settle in.",
          45,
        ),
        message(
          "maya",
          "Final walkthrough at 14:00? We can check the whole flow together.",
          47,
        ),
        message(
          "alex",
          "See you there. Thanks for bringing this together, everyone! 🙌",
          49,
        ),
      ],
);
launch.rows[0].reply_count = 3;
launch.rows[2].pinned = true;
launch.rows[3].reactions = [
  { emoji: "🙌", count: 3, mine: true, people: ["alex", "maya", "jules"] },
];
launch.rows[7].reply_count = 4;
launch.rows[9].pinned = true;
launch.rows[10].reactions = [
  { emoji: "💚", count: 3, mine: true, people: ["alex", "maya", "sam"] },
];
const general = chat(
  "General",
  "general",
  family
    ? [
        message("sam", "Welcome to our little family corner! 💛", 12, true),
        message(
          "maya",
          "How is everyone’s week going? Send a photo when you get a moment.",
          46,
          true,
        ),
      ]
    : [
        message("sam", "Welcome to Studio North. Say hello!", 12, true),
        message(
          "maya",
          "A warm welcome to everyone joining us this week. What are you working on?",
          46,
          true,
        ),
      ],
);
general.is_general = true;
const design = chat(
  family ? "Weekend away" : "Design room",
  "design",
  family
    ? [
        message("maya", "A little cabin by the lake. Who’s in?", 32, true),
        message("sam", "Yes please! I’ll bring the board games.", 41, true),
        message("jules", "I can drive. There’s room for everyone.", 44, true),
      ]
    : [
        message(
          "maya",
          "Two new directions for the packaging. Which one feels right?",
          32,
          true,
        ),
        message(
          "sam",
          "The second direction gives the illustrations more room to breathe.",
          41,
          true,
        ),
        message(
          "maya",
          "Agreed. I’ll bring the softer palette into the next round.",
          44,
          true,
        ),
      ],
);
design.rows[0].reply_count = 5;
const plans = chat(
  family ? "Sunday lunch" : "Weekly plans",
  "plans",
  family
    ? [
        message(
          "jules",
          "Lunch at ours this Sunday? Come around one.",
          30,
          true,
        ),
        message("sam", "We’ll be there. I’m bringing apple pie!", 42, true),
      ]
    : [
        message(
          "jules",
          "Tomorrow’s priorities are ready. Add yours before we meet.",
          30,
          true,
        ),
        message(
          "sam",
          "My focus is the welcome guide and a first round of customer conversations.",
          42,
          true,
        ),
      ],
);
const direct = chat(
  family ? "Mom" : "Maya",
  "maya",
  family
    ? [
        message("maya", "Did you find the birthday candles?", 14),
        message("alex", "Yes! Sam has them. Everything is ready.", 16),
        message("maya", "Lovely. See you on Saturday! 💛", 39),
      ]
    : [
        message("maya", "Have a minute to look at the new concept?", 14),
        message("alex", "Absolutely. The softer palette is my favourite.", 16),
        message("maya", "Same here! I’ll share it with the team.", 39),
      ],
  true,
);
direct.members = direct.members.filter((member) =>
  ["alex", "maya"].includes(member.identity_id),
);
const otherChats = (
  family
    ? [
        chat("Family photos", "photos", [
          message(
            "jules",
            "Found this one from our first camping trip. Remember the rain?",
            38,
            true,
          ),
        ]),
        chat("Movie night", "movies", [
          message(
            "sam",
            "Something funny this Friday? I’ll bring popcorn.",
            35,
            true,
          ),
        ]),
        chat("Recipes", "recipes", [
          message(
            "maya",
            "Grandma’s apple cake recipe, exactly as she wrote it.",
            33,
            true,
          ),
        ]),
        chat("Little moments", "moments", [
          message("sam", "First day at the new job. Wish me luck!", 31, true),
        ]),
        chat("Garden plans", "garden", [
          message(
            "jules",
            "The tomatoes are finally ready. Come and pick some! 🍅",
            29,
          ),
        ]),
        chat("Holiday ideas", "holidays", [
          message("alex", "Mountains or the seaside this summer?", 27),
        ]),
        chat("Book club", "books", [
          message(
            "maya",
            "Finished the last chapter. We need to talk about that ending!",
            25,
          ),
        ]),
      ]
    : [
        chat("Product ideas", "ideas", [
          message(
            "jules",
            "What would make your first five minutes here feel easier?",
            38,
            true,
          ),
        ]),
        chat("Customer stories", "stories", [
          message(
            "maya",
            "The first team shared their feedback. Lots of good ideas to bring back.",
            35,
            true,
          ),
        ]),
        chat("Release notes", "releases", [
          message(
            "sam",
            "A clearer welcome, quieter notifications, and a little more personality.",
            33,
            true,
          ),
        ]),
        chat("Team rituals", "rituals", [
          message(
            "jules",
            "Friday show-and-tell: bring one thing you learned this week.",
            31,
            true,
          ),
        ]),
        chat("Coffee break", "coffee", [
          message(
            "maya",
            "Today’s important question: where is the best coffee near the studio? ☕",
            29,
          ),
        ]),
        chat("Inspiration", "inspiration", [
          message(
            "sam",
            "A small collection of things that made us stop and look.",
            27,
          ),
        ]),
        chat("Book club", "books", [
          message(
            "jules",
            "Next chapter, next Thursday. Everyone is welcome.",
            25,
          ),
        ]),
      ]
).map((stream) => ({ ...stream, group: null }));
const streams = [general, launch, design, plans, direct, ...otherChats];
const view: View = {
  identity: "alex",
  credential: "alex-device",
  name: "Alex",
  paged: false,
  active_space: "studio",
  space_setup: false,
  spaces: [
    {
      id: "studio",
      name: family ? "Our family" : "Studio North",
      status: "joined",
      owner: true,
      requests: 0,
      managed: true,
    },
    {
      id: "field",
      name: family ? "Studio North" : "Fieldwork",
      status: "joined",
      owner: false,
      requests: 0,
      managed: true,
    },
    {
      id: "paper",
      name: family ? "Book club" : "Paper Planes",
      status: "joined",
      owner: false,
      requests: 0,
      managed: true,
    },
    {
      id: "makers",
      name: "Weekend Makers",
      status: "joined",
      owner: false,
      requests: 0,
      managed: true,
    },
    {
      id: "circle",
      name: family ? "Neighbours" : "Design Circle",
      status: "joined",
      owner: false,
      requests: 0,
      managed: true,
    },
    {
      id: "demo",
      name: family ? "Old friends" : "Demo",
      status: "joined",
      owner: false,
      requests: 0,
      managed: true,
    },
  ],
  contacts: Object.entries(people)
    .filter(([id]) => id !== "alex")
    .map(([id, name]) => ({ id, name })),
  demo_names: people,
  streams,
  groups: [{ id: "work", name: family ? "Family" : "Studio" }],
  reminders: [
    { stream: "launch", record: launch.rows[2].id, due_at: 1789380000000 },
    { stream: "design", record: design.rows[0].id, due_at: 1789387200000 },
    { stream: "plans", record: plans.rows[0].id, due_at: 1789398000000 },
  ],
  invitations: {
    enabled: true,
    pending: 0,
    responses: 0,
    actionable: 0,
    notifications: 0,
  },
  replicas: [],
  counts: {
    pending: 0,
    stored: streams.reduce((count, stream) => count + stream.rows.length, 0),
    held: 0,
    rejected: 0,
    repair_pending: 0,
  },
  inbox: {},
  history_warning: "",
  alpha_ready: false,
};
mockIPC(
  (command, payload) => {
    if (command === "profile_environment")
      return {
        mobile: true,
        has_profile: true,
        directory: "marketing-only",
        demo_helpers: false,
        saved_profiles: [],
        demo_space_id: "demo",
      };
    if (command === "unlock") return view;
    if (command === "push_task")
      return { available: false, enabled: false, pending: false };
    if (command === "plugin:deep-link|get_current") return null;
    if (command.includes("biometry"))
      return { isAvailable: false, biometryType: 0 };
    if (command === "plugin:notification|pending_action") return null;
    if (command === "operate") {
      const request = (
        payload as { request?: { op?: string; space_id?: string } }
      )?.request;
      if (request?.op === "space_switch" && request.space_id)
        view.active_space = request.space_id;
      return {
        view,
        result: { offers: [], requests: [] },
        received: [],
        incoming: [],
        errors: [],
      };
    }
    console.debug("Marketing fixture ignored IPC", command);
    return null;
  },
  { shouldMockEvents: true },
);
await import("../src/main");
