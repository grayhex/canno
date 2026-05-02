# Design System Discovery: Linear / Modern Integration

## 1) Current Frontend Mental Model

### Tech stack
- **Backend-rendered web app on Python stdlib HTTP server** (`ThreadingHTTPServer`) with handcrafted handlers.
- **No React/Next/Vue/Tailwind/shadcn** currently in use.
- **Styling is plain global CSS** in `static.css`.
- **HTML appears template-generated** in `canno/templates/html.py` (server-side string templates).

### Existing design tokens and visual language
Current token surface is centralized in CSS custom properties under `:root`:
- Colors: `--bg`, `--bg-soft`, `--card`, `--stroke`, `--text`, `--muted`, `--primary`, `--primary-2`, etc.
- Radius and elevation are currently component-level via literal values (10px, 12px, 14px, 16px) and one-layer shadows.
- Gradients are already used, but not yet as a multi-layer cinematic ambient system.

### Utility and component patterns
- Pattern is **class-based reusable blocks** (e.g., `.card`, `.btn-secondary`, `.tabs`, `.block`, `.nav-links`).
- Architecture is closer to **flat global styles + semantic sections** than strict atomic design.
- Responsiveness currently has a single mobile media query around 640px.

### Constraints
- Legacy/global CSS approach means changes must avoid selector collisions.
- No utility framework means design system should be introduced as:
  1) centralized CSS variables, then
  2) composable class primitives, then
  3) incremental template upgrades.
- Bundle/performance: lightweight stack; avoid heavy JS dependencies for animation.

---

## 2) Recommended Integration Direction (Idiomatic for Current Stack)

1. **Token Layer First**
   - Expand `:root` into a complete token set for your Linear/Modern spec (background tiers, foreground tiers, accent, border, glow, motion, radii, shadows).
   - Add semantic aliases to keep template classes readable.

2. **Foundation Primitives**
   - Add reusable primitives in CSS:
     - `ds-surface`, `ds-card`, `ds-button-primary`, `ds-button-secondary`, `ds-input`, `ds-focus-ring`.
   - Keep existing classes as wrappers to reduce migration risk.

3. **Ambient Background System**
   - Implement layered background with pseudo-elements and optional blob elements.
   - Add `prefers-reduced-motion` fallback to disable blob/parallax motion.

4. **Progressive Component Refactor**
   - Migrate high-visibility screens first (home/login/admin dashboard shell).
   - Then migrate tabs/forms/tables and quest flow screens.

5. **Interaction Polish + Accessibility**
   - Standardize focus ring, hover deltas, active scale, and animation durations.
   - Validate contrast and keyboard states per role screens.

---

## 3) Focused Scope Questions

Please choose one path so implementation can be scoped correctly:

1. **What should be redesigned first?**
   - A) Specific page (tell me URL/route)
   - B) Shared components (buttons/cards/inputs/tables)
   - C) Full visual refactor across app

2. **How far should motion go in v1?**
   - A) Full cinematic (animated blobs + parallax + spotlight)
   - B) Moderate (ambient layers + subtle hover/focus, minimal continuous motion)
   - C) Static-first (no continuous animation; accessibility-first baseline)

3. **Do you want us to keep the current CSS-only stack** (recommended for minimal risk),
   or introduce a utility framework (Tailwind) in this repo?

4. **Any screens that must remain visually unchanged** for operational reasons (e.g., admin tables during live events)?

5. **Do you want a phased rollout plan** with feature flags/class gates so old and new styles can coexist during migration?
