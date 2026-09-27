# GhostSOC interface design system

GhostSOC uses a restrained SOC-workstation visual language: solid neutral surfaces, compact grids, subtle borders, low radii, no decorative charts, no glassmorphism, and no non-state gradients. Color is reserved for severity, health, response, and selection state.

## Shared system

- Grouped navigation: Monitor, Investigate, Manage.
- Consistent page heading, eyebrow, panels, tables, badges, buttons, form controls, loading state, empty state, success/error feedback, and focus outline.
- Tables use sticky headers, bounded horizontal scrolling, hover state, and keyboard-operable detail rows.
- Operational statistics are returned by the backend; absent data is labeled `NO DATA`, `WAITING FOR EVENTS`, `NOT CONFIGURED`, or the actual degraded state.
- The tablet breakpoint moves navigation to a compact horizontally scrollable top bar.

## Primary workspaces

- **SOC mode / Overview:** clickable command metrics, real health-aware top bar, global search, notifications, event/attack/incident/response trends, severity and attack distributions, live attack relationship graph, events, ATT&CK coverage, and incident queue.
- **Network mode:** aggregated communication topology with time range, search, severity/type/suspicious filters, wheel/button zoom, drag pan, fit/reset, keyboard selection, node/edge inspection, and direct incident navigation.
- **Investigate mode / Incidents:** compact command header with severity/status/risk and tabs for Summary, Attack graph, Evidence & IOCs, Timeline, and Response & audit. The response console displays policy guardrails, only server-derived targets, impact/approval requirements, explicit confirmation, approval/denial reason capture, SSE updates, execution/verification states, audit, and report exports.
- **Live Monitor:** SSE connection state, search, severity/type/source/endpoint/time filters, sorting, pagination, keyboard rows, and event detail drawer.
- **Attacks:** table/relationship-graph switch, aggregated detections, and unified attack investigation drawer.
- **Web Security:** real rates, severity, sources, attack types, targets, risk, connector/system health, replay, and normalized requests.
- **Integrations:** uniform adapter inventory with status, capabilities, enable/disable, and connection test.

## Accessibility and interaction

- Native buttons and form labels/ARIA labels.
- `aria-current` for navigation and incident tabs.
- Visible `:focus-visible` outlines.
- Enter/Space activation for live request and attack table rows.
- Labeled drawer close controls.
- Purposeful loading and empty states without decorative animation.

## Executed UI gate

A real Chromium session opened every navigation page, SOC charts, global search, notifications, table pagination, table/graph attack modes, network topology, incident graph, request drawer, and attack drawer. Desktop width was 1500×1000 and tablet width 900×900. The gate verified no page/console errors, no horizontal overflow, four live filter selects, keyboard row activation, 44-row pagination, four network nodes from actual telemetry, 19 attack graph nodes, 31 current incident entities aggregated into non-overlapping visual nodes, edge selection, zoom, direct search navigation, a 90px tablet navigation bar, all 20 integration cards after rapid page changes, and a complete `BLOCK_SOURCE` request → approval → `DRY_RUN` verification with five visible policy guardrails and no layout overflow.
