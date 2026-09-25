import { useEffect, useState } from "react";
import {
  ArrowUp,
  ArrowDown,
  ArrowRightLeft,
  Pin,
  Smile,
  Copy,
  MessageSquareDot,
  Check,
  FileText,
  Flag,
  Bell,
  BellOff,
  ChevronLeft,
  ChevronRight,
  Clock,
  CloudCheck,
  Ellipsis,
  Eye,
  EyeOff,
  Globe,
  Hash,
  Inbox,
  Image,
  Camera,
  Info,
  LockKeyhole,
  Layers2,
  MessageSquareText,
  MessagesSquare,
  Moon,
  OctagonX,
  Palette,
  Paperclip,
  Pencil,
  Plus,
  Power,
  QrCode,
  RefreshCw,
  Reply,
  Search,
  Settings,
  Share,
  ShieldCheck,
  SlidersHorizontal,
  Smartphone,
  SquareCheck,
  SquareExclamationPoint,
  createLucideIcon,
  Sun,
  TriangleAlert,
  Trash2,
  Type,
  UserRound,
  UsersRound,
  Volume2,
  X,
  type LucideIcon,
} from "lucide-react";
import { t } from "./i18n";

// Import individual icons so the bundle only includes this shared selection.
// Lucide/Feather notices are distributed in public/licenses/lucide.txt.
// Adapt Lucide Clock and RefreshCw to the shared square status frame.
const SquareClock = createLucideIcon("SquareClock", [
  [
    "rect",
    { x: "3", y: "3", width: "18", height: "18", rx: "2", key: "frame" },
  ],
  ["path", { d: "M12 8v4l3 2", key: "hands" }],
]);
const SquareSync = createLucideIcon("SquareSync", [
  [
    "rect",
    { x: "3", y: "3", width: "18", height: "18", rx: "2", key: "frame" },
  ],
  [
    "path",
    { d: "M7 12a5 5 0 0 1 5-5 5.5 5.5 0 0 1 3.7 1.5L17 10", key: "top" },
  ],
  ["path", { d: "M17 7v3h-3", key: "top-arrow" }],
  [
    "path",
    { d: "M17 12a5 5 0 0 1-5 5 5.5 5.5 0 0 1-3.7-1.5L7 14", key: "bottom" },
  ],
  ["path", { d: "M10 14H7v3", key: "bottom-arrow" }],
]);
const icons = {
  pin: Pin,
  smile: Smile,
  copy: Copy,
  clock: Clock,
  unread: MessageSquareDot,
  queued: SquareClock,
  synced: SquareCheck,
  syncPending: SquareSync,
  syncIssue: SquareExclamationPoint,
  reply: Reply,
  check: Check,
  delete: Trash2,
  file: FileText,
  attachment: Paperclip,
  image: Image,
  camera: Camera,
  flag: Flag,
  edit: Pencil,
  eye: Eye,
  eyeOff: EyeOff,
  bell: Bell,
  muted: BellOff,
  search: Search,
  close: X,
  inbox: Inbox,
  qr: QrCode,
  share: Share,
  back: ChevronLeft,
  next: ChevronRight,
  up: ArrowUp,
  down: ArrowDown,
  plus: Plus,
  power: Power,
  sync: RefreshCw,
  lock: LockKeyhole,
  chats: MessageSquareText,
  hash: Hash,
  conversations: MessagesSquare,
  actions: SlidersHorizontal,
  spaceSwitch: ArrowRightLeft,
  spaces: Layers2,
  settings: Settings,
  person: UserRound,
  people: UsersRound,
  sun: Sun,
  moon: Moon,
  device: Smartphone,
  verified: ShieldCheck,
  stored: CloudCheck,
  warning: TriangleAlert,
  waiting: Clock,
  rejected: OctagonX,
  info: Info,
  palette: Palette,
  globe: Globe,
  text: Type,
  more: Ellipsis,
  volume: Volume2,
} as const satisfies Record<string, LucideIcon>;

export type IconName = keyof typeof icons | "buzz";

// Two mirrored Lucide Speech profiles with a shared conversation bubble.
// This adaptation is covered by the bundled Lucide notice above.
function BuzzIcon({ attention }: { attention: boolean }) {
  const [firstSpeaker, setFirstSpeaker] = useState(() =>
    Math.random() < 0.5 ? "left" : "right",
  );
  useEffect(() => {
    if (!attention) return;
    const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
    let timer: ReturnType<typeof setInterval> | undefined;
    const update = () => {
      clearInterval(timer);
      if (!motion.matches) {
        timer = setInterval(() => {
          if (!document.hidden)
            setFirstSpeaker(Math.random() < 0.5 ? "left" : "right");
        }, 8000);
      }
    };
    update();
    motion.addEventListener("change", update);
    return () => {
      clearInterval(timer);
      motion.removeEventListener("change", update);
    };
  }, [attention]);
  const profile =
    "M8.8 20v-4.1l1.9.2a2.3 2.3 0 0 0 2.164-2.1V8.3A5.37 5.37 0 0 0 2 8.25c0 2.8.656 3.054 1 4.55a5.77 5.77 0 0 1 .029 2.758L2 20";
  return (
    <svg
      className="ui-icon buzz-icon"
      data-chattering={attention || undefined}
      data-first-speaker={firstSpeaker}
      width={24}
      height={24}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <g className="buzz-speaker">
        <path
          d={profile}
          transform="translate(0 10.5) scale(.65)"
          strokeWidth={2.6923}
        />
      </g>
      <g className="buzz-listener">
        <path
          d={profile}
          transform="translate(24 10.5) scale(-.65 .65)"
          strokeWidth={2.6923}
        />
      </g>
      <g className="buzz-words" strokeWidth={1.3}>
        <path d="m10 16.3 1.8-.7 M10.3 18.5h2" />
      </g>
      <path
        className="buzz-bubble"
        d="M9 2.5h6a1.5 1.5 0 0 1 1.5 1.5v2A1.5 1.5 0 0 1 15 7.5h-2l-2 2v-2H9A1.5 1.5 0 0 1 7.5 6V4A1.5 1.5 0 0 1 9 2.5Z"
      />
    </svg>
  );
}

export function Icon({
  name,
  attention = false,
}: {
  name: IconName;
  attention?: boolean;
}) {
  if (name === "buzz") return <BuzzIcon attention={attention} />;
  const Component = icons[name];
  return (
    <Component
      className="ui-icon"
      size={24}
      strokeWidth={1.75}
      fill={name === "more" ? "currentColor" : "none"}
      aria-hidden="true"
      focusable="false"
    />
  );
}

export function NewIndicator() {
  return (
    <span
      className="new-indicator"
      role="img"
      aria-label={t("notifications.new")}
    />
  );
}
